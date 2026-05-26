"""
Blast radius analyser.

Given a compromised NHI, answers:
  - What identities can an attacker directly reach? (1-hop)
  - What is the full propagation path? (BFS through identity graph)
  - Which other NHIs have similar exposure? (pgvector cosine similarity)
  - What is the APRA-reportable impact summary?
"""
import structlog
from collections import deque
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from ..models.nhi import NHIIdentity, AuditLog, RiskLevel
from ..models.graph import IdentityRelationship, RelationshipType

log = structlog.get_logger()


class BlastRadiusService:

    async def calculate(self, db: AsyncSession, nhi_id: int, max_depth: int = 6) -> dict:
        """
        BFS from compromised NHI through identity relationship graph.
        Returns all reachable identities with hop count and traversal path.
        """
        origin = await db.get(NHIIdentity, nhi_id)
        if not origin:
            return {"error": "NHI not found"}

        visited: dict[int, dict] = {}  # id -> {depth, path, risk}
        queue: deque[tuple[int, int, list[int]]] = deque([(nhi_id, 0, [nhi_id])])

        while queue:
            current_id, depth, path = queue.popleft()
            if current_id in visited or depth > max_depth:
                continue
            visited[current_id] = {"depth": depth, "path": path}

            edges = await db.scalars(
                select(IdentityRelationship).where(IdentityRelationship.source_id == current_id)
            )
            for edge in edges.all():
                if edge.target_id not in visited:
                    queue.append((edge.target_id, depth + 1, path + [edge.target_id]))

        # Fetch NHI details for all reachable nodes (exclude origin itself)
        reachable_ids = [i for i in visited if i != nhi_id]
        reachable_nhis: list[NHIIdentity] = []
        for rid in reachable_ids:
            nhi = await db.get(NHIIdentity, rid)
            if nhi:
                reachable_nhis.append(nhi)

        critical_count = sum(1 for n in reachable_nhis if n.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for n in reachable_nhis if n.risk_level == RiskLevel.HIGH)

        similar = await self._find_similar_exposure(db, nhi_id)

        result = {
            "origin": {
                "id": origin.id,
                "name": origin.name,
                "provider": origin.provider,
                "risk_level": origin.risk_level,
            },
            "blast_radius": {
                "total_reachable": len(reachable_ids),
                "max_depth_reached": max(v["depth"] for v in visited.values()) if visited else 0,
                "critical_reachable": critical_count,
                "high_reachable": high_count,
                "overall_severity": self._severity(critical_count, high_count, len(reachable_ids)),
            },
            "reachable_identities": [
                {
                    "id": n.id,
                    "name": n.name,
                    "provider": n.provider,
                    "credential_type": n.credential_type,
                    "risk_level": n.risk_level,
                    "hop_count": visited[n.id]["depth"],
                    "attack_path": visited[n.id]["path"],
                }
                for n in reachable_nhis
            ],
            "similar_exposure_nhis": similar,
            "apra_cps234": {
                "incident_scope": f"{len(reachable_ids)} identities reachable from compromised credential '{origin.name}'",
                "critical_systems_at_risk": critical_count,
                "max_lateral_movement_hops": max(v["depth"] for v in visited.values()) if visited else 0,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

        await self._write_audit(db, nhi_id=nhi_id, detail={
            "reachable": len(reachable_ids),
            "critical": critical_count,
            "severity": result["blast_radius"]["overall_severity"],
        })

        log.info("blast_radius_calculated", origin_id=nhi_id, reachable=len(reachable_ids),
                 critical=critical_count)
        return result

    async def _find_similar_exposure(self, db: AsyncSession, nhi_id: int, top_k: int = 5) -> list[dict]:
        """
        pgvector cosine similarity — find NHIs with similar access patterns.
        These are lateral movement candidates even without explicit graph edges.
        """
        origin = await db.get(NHIIdentity, nhi_id)
        if origin is None or origin.access_pattern_embedding is None:
            return []

        rows = await db.execute(
            text("""
                SELECT id, name, provider, risk_level,
                       1 - (access_pattern_embedding <=> :embedding) AS similarity
                FROM nhi_identities
                WHERE id != :origin_id
                  AND access_pattern_embedding IS NOT NULL
                  AND is_active = true
                ORDER BY access_pattern_embedding <=> :embedding
                LIMIT :k
            """),
            {"embedding": str(origin.access_pattern_embedding), "origin_id": nhi_id, "k": top_k},
        )
        return [
            {"id": r.id, "name": r.name, "provider": r.provider,
             "risk_level": r.risk_level, "similarity": round(float(r.similarity), 4)}
            for r in rows
        ]

    async def build_graph_from_scan(self, db: AsyncSession) -> dict:
        """
        Infer identity relationships from existing NHI data.
        Called after each cloud scan to keep graph current.
        """
        nhis = await db.scalars(select(NHIIdentity).where(NHIIdentity.is_active == True))
        all_nhis = list(nhis.all())

        edges_created = 0
        edges_created += await self._infer_aws_role_chains(db, all_nhis)
        edges_created += await self._infer_agent_ownership(db, all_nhis)
        await db.commit()

        log.info("identity_graph_built", nhis=len(all_nhis), edges=edges_created)
        return {"nhis_processed": len(all_nhis), "edges_created": edges_created}

    async def _infer_aws_role_chains(self, db: AsyncSession, nhis: list[NHIIdentity]) -> int:
        """
        IAM roles that allow sts:AssumeRole on other roles create can_assume edges.
        Lambda execution roles → their IAM role create delegates_to edges.
        """
        count = 0
        roles = [n for n in nhis if "role" in (n.credential_type or "")]
        lambda_accounts = [n for n in nhis if n.owner_agent and "lambda" in n.name]

        for fn in lambda_accounts:
            # Lambda function → its execution role
            for role in roles:
                if role.name and fn.metadata_raw and role.name in str(fn.metadata_raw.get("role_arn", "")):
                    count += await self._upsert_edge(
                        db, fn.id, role.id, RelationshipType.DELEGATES_TO,
                        provider="aws", detail=f"lambda {fn.name} executes as {role.name}"
                    )

        # Over-privileged roles can reach everything — connect to all critical NHIs
        op_roles = [n for n in roles if n.is_over_privileged]
        critical_nhis = [n for n in nhis if n.risk_level == RiskLevel.CRITICAL]
        for role in op_roles:
            for target in critical_nhis:
                if role.id != target.id:
                    count += await self._upsert_edge(
                        db, role.id, target.id, RelationshipType.PEER_ACCESS,
                        provider="aws", detail="over-privileged role has lateral access path"
                    )
        return count

    async def _infer_agent_ownership(self, db: AsyncSession, nhis: list[NHIIdentity]) -> int:
        """
        AI agent credentials inherit from their parent service account.
        """
        count = 0
        agents = [n for n in nhis if n.credential_type == "agent_credential" and n.owner_agent]
        service_accounts = [n for n in nhis if n.credential_type == "service_account"]
        for agent in agents:
            for svc in service_accounts:
                if agent.owner_agent and svc.name and agent.owner_agent in svc.name:
                    count += await self._upsert_edge(
                        db, agent.id, svc.id, RelationshipType.INHERITS_FROM,
                        provider=agent.provider, detail=f"agent {agent.name} inherits {svc.name}"
                    )
        return count

    async def _upsert_edge(self, db: AsyncSession, source: int, target: int,
                           rel_type: RelationshipType, provider: str = "", detail: str = "") -> int:
        existing = await db.scalar(
            select(IdentityRelationship).where(
                IdentityRelationship.source_id == source,
                IdentityRelationship.target_id == target,
                IdentityRelationship.relationship_type == rel_type,
            )
        )
        if existing:
            return 0
        edge = IdentityRelationship(source_id=source, target_id=target,
                                    relationship_type=rel_type, provider=provider, detail=detail)
        db.add(edge)
        return 1

    def _severity(self, critical: int, high: int, total: int) -> str:
        if critical > 0:
            return "critical"
        if high > 2 or total > 20:
            return "high"
        if high > 0 or total > 5:
            return "medium"
        return "low"

    async def _write_audit(self, db: AsyncSession, nhi_id: int, detail: dict):
        entry = AuditLog(
            event_type="blast_radius_analysis",
            actor="agentguard:blast-radius",
            action="calculate_blast_radius",
            identity_id=nhi_id,
            outcome="success",
            detail=detail,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(entry)
        await db.commit()
