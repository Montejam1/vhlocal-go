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
# stub line 12
# stub line 13
# stub line 14
# stub line 15
# stub line 16
# stub line 17
# stub line 18
# stub line 19
# stub line 20
# stub line 21
# stub line 22
# stub line 23
# stub line 24
# stub line 25
# stub line 26
# stub line 27

@router.get("/jobs")
def api_list_jobs(
    status: models.JobStatus | None = None,
    region_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
# stub line 36
# stub line 37
# stub line 38
# stub line 39
    query = db.query(models.Job)
    if user.role == models.UserRole.dispatcher:
        rids = dispatcher_region_ids(db, user)
        query = query.filter(models.Job.region_id.in_(rids))
    if status:
        query = query.filter(models.Job.status == status)
    if region_id:
        query = query.filter(models.Job.region_id == region_id)
    rows = query.order_by(models.Job.scheduled_start.asc()).offset(offset).limit(limit).all()
    return {"items": [schemas.JobOut.model_validate(r).model_dump() for r in rows]}
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
    job = db.query(models.Job).filter(models.Job.id == job_id).one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")
    if not user_can_modify_job(db, user, job):
        raise HTTPException(status_code=403, detail="Forbidden")
    allowed = models.JOB_STATUS_TRANSITIONS.get(job.status, set())
    if payload.status not in allowed:
# stub line 67
# stub line 68
# stub line 69
            has_proof = db.query(models.Proof).filter(models.Proof.job_id == job.id).first()
            if not has_proof:
                raise HTTPException(status_code=400, detail="Proof required")
    old = job.status
    job.status = payload.status
    now = datetime.now(timezone.utc)
    if payload.status == models.JobStatus.in_progress and not job.started_at:
        job.started_at = now
    if payload.status == models.JobStatus.completed:
        job.completed_at = now
    if payload.status == models.JobStatus.failed:
        job.failure_reason = payload.failure_reason or "Failed"
    db.add(job)
    write_audit(db, actor=user, action="api.job.status_change", target_type="job", target_id=job.id,
                details={"from": old.value, "to": payload.status.value}, ip_address=get_client_ip(request))
    db.commit()
