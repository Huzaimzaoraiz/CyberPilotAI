from fastapi import APIRouter
from .routers import targets, assets, vulnerabilities, tasks, attack_paths, remediation, session, models, scans, reports

router = APIRouter(prefix="/api/v1")

router.include_router(targets.router, tags=["Targets"])
router.include_router(assets.router, tags=["Assets"])
router.include_router(vulnerabilities.router, tags=["Vulnerabilities"])
router.include_router(tasks.router, tags=["Tasks"])
router.include_router(attack_paths.router, tags=["Attack Paths"])
router.include_router(remediation.router, tags=["Remediation"])
router.include_router(session.router, tags=["Session"])
router.include_router(models.router, tags=["Models"])
router.include_router(scans.router, tags=["Scans"])
router.include_router(reports.router, tags=["Reports"])
