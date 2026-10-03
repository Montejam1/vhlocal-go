# stub line 1
# stub line 2
# stub line 3
# stub line 4
# stub line 5
# stub line 6
# stub line 7
# stub line 8
# stub line 9
# stub line 10
# stub line 11
router = APIRouter(prefix="/api/workers", tags=["workers"])


@router.get("", response_model=list[schemas.WorkerOut])
def list_workers(
    region_id: str | None = None,
    availability: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
# stub line 21
# stub line 22
# stub line 23
    if user.role == models.UserRole.customer:
        raise HTTPException(status_code=403, detail="Forbidden")
    query = db.query(models.Worker)
    if region_id:
        query = query.filter(models.Worker.region_id == region_id)
    if availability:
        query = query.filter(models.Worker.availability == availability)
    if user.role == models.UserRole.field_worker:
# stub line 32
# stub line 33
# stub line 34
# stub line 35
# stub line 36
# stub line 37
# stub line 38
# stub line 39
# stub line 40
# stub line 41
# stub line 42
# stub line 43
# stub line 44
# stub line 45
# stub line 46
# stub line 47
# stub line 48
# stub line 49
# stub line 50
# stub line 51
# stub line 52
# stub line 53
# stub line 54
# stub line 55
# stub line 56
# stub line 57
# stub line 58
# stub line 59
# stub line 60
# stub line 61
# stub line 62
# stub line 63
# stub line 64
# stub line 65
# stub line 66
# stub line 67
# stub line 68
# stub line 69
@router.get("/{worker_id}", response_model=schemas.WorkerOut)
def get_worker(
    worker_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if user.role == models.UserRole.customer:
        raise HTTPException(status_code=403, detail="Forbidden")
    w = db.query(models.Worker).filter(models.Worker.id == worker_id).one_or_none()
    if not w:
        raise HTTPException(status_code=404, detail="Not found")
    if user.role == models.UserRole.field_worker and (not user.worker or user.worker.id != w.id):
        raise HTTPException(status_code=403, detail="Forbidden")
    return w
