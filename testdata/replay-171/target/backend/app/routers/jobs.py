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
# stub line 28
# stub line 29
# stub line 30
# stub line 31
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


@router.get("")
def list_jobs(
    region_id: str | None = None,
    worker_id: str | None = None,
    status: models.JobStatus | None = None,
# stub line 67
# stub line 68
# stub line 69
# stub line 70
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    query = db.query(models.Job)
    query = _filter_jobs_for_user(db, user, query)
    if region_id:
        query = query.filter(models.Job.region_id == region_id)
    if worker_id:
        query = query.filter(models.Job.assigned_worker_id == worker_id)
    if status:
        query = query.filter(models.Job.status == status)
    if priority:
        query = query.filter(models.Job.priority == priority)
    if customer_id:
        query = query.filter(models.Job.customer_id == customer_id)
    if date_from:
        query = query.filter(models.Job.scheduled_start >= date_from)
    if date_to:
        query = query.filter(models.Job.scheduled_start <= date_to)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(models.Job.code.ilike(like) | models.Job.description.ilike(like))
# stub line 96
# stub line 97
# stub line 98
# stub line 99
# stub line 100
# stub line 101
# stub line 102
# stub line 103
# stub line 104
# stub line 105
# stub line 106
# stub line 107
):
    if user.role not in (models.UserRole.ops_admin, models.UserRole.dispatcher):
        raise HTTPException(status_code=403, detail="Forbidden")
# stub line 111
    customer = db.query(models.Customer).filter(models.Customer.id == payload.customer_id).one_or_none()
    if not customer:
        raise HTTPException(status_code=400, detail="Invalid customer")
    location = db.query(models.ServiceLocation).filter(
        models.ServiceLocation.id == payload.location_id,
        models.ServiceLocation.customer_id == payload.customer_id,
    ).one_or_none()
# stub line 119
# stub line 120
# stub line 121
# stub line 122
# stub line 123
    assert_dispatcher_can_access_region(db, user, location.region_id)
# stub line 125
    job = models.Job(
        code=_gen_job_code(db),
        customer_id=payload.customer_id,
        location_id=payload.location_id,
        region_id=location.region_id,
        service_type_id=payload.service_type_id,
        priority=payload.priority,
        scheduled_start=payload.scheduled_start,
# stub line 134
# stub line 135
# stub line 136
# stub line 137
# stub line 138
# stub line 139
# stub line 140
# stub line 141
# stub line 142
# stub line 143
# stub line 144
# stub line 145
# stub line 146
# stub line 147
# stub line 148
# stub line 149
# stub line 150
# stub line 151
# stub line 152
# stub line 153
# stub line 154
# stub line 155
# stub line 156
# stub line 157
# stub line 158
# stub line 159
# stub line 160
# stub line 161
# stub line 162
# stub line 163
# stub line 164
# stub line 165
# stub line 166
# stub line 167
# stub line 168
# stub line 169
# stub line 170
# stub line 171
# stub line 172
# stub line 173
# stub line 174
# stub line 175
# stub line 176
# stub line 177
# stub line 178
# stub line 179
# stub line 180
# stub line 181
# stub line 182
# stub line 183
# stub line 184
# stub line 185
# stub line 186
# stub line 187
# stub line 188
# stub line 189
# stub line 190
# stub line 191
# stub line 192
# stub line 193
# stub line 194
# stub line 195
# stub line 196
# stub line 197
# stub line 198
# stub line 199
# stub line 200
# stub line 201
# stub line 202
# stub line 203
# stub line 204
# stub line 205
# stub line 206
# stub line 207
# stub line 208
# stub line 209
# stub line 210
# stub line 211
# stub line 212
# stub line 213
# stub line 214
# stub line 215
# stub line 216
# stub line 217
# stub line 218
# stub line 219
# stub line 220
# stub line 221
# stub line 222
# stub line 223
# stub line 224
# stub line 225
# stub line 226
# stub line 227
# stub line 228
# stub line 229
# stub line 230
# stub line 231
# stub line 232
# stub line 233
# stub line 234
# stub line 235
# stub line 236
# stub line 237
# stub line 238
# stub line 239
# stub line 240
# stub line 241
# stub line 242
# stub line 243
# stub line 244
# stub line 245
# stub line 246
# stub line 247
# stub line 248
# stub line 249
# stub line 250
# stub line 251
# stub line 252
# stub line 253
# stub line 254
# stub line 255
# stub line 256
# stub line 257
# stub line 258
# stub line 259
# stub line 260
# stub line 261
# stub line 262
# stub line 263
# stub line 264
# stub line 265
# stub line 266
# stub line 267
    job = db.query(models.Job).filter(models.Job.id == job_id).one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")
    if not user_can_modify_job(db, user, job):
        raise HTTPException(status_code=403, detail="Forbidden")

    # Field workers can only do operational transitions, not cancel
    new_status = payload.status
    if user.role == models.UserRole.field_worker and new_status == models.JobStatus.cancelled:
        raise HTTPException(status_code=403, detail="Workers cannot cancel jobs")
    if user.role == models.UserRole.field_worker and new_status == models.JobStatus.assigned:
        raise HTTPException(status_code=403, detail="Workers cannot reassign jobs")

    allowed = models.JOB_STATUS_TRANSITIONS.get(job.status, set())
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid transition from {job.status.value} to {new_status.value}")

    # Completion requires proof when service type requires it
    if new_status == models.JobStatus.completed:
        if job.service_type and job.service_type.requires_proof:
            has_proof = db.query(models.Proof).filter(models.Proof.job_id == job.id).first()
            if not has_proof:
                raise HTTPException(status_code=400, detail="Proof is required to complete this job")

    old = job.status
    job.status = new_status
    now = datetime.now(timezone.utc)
    if new_status == models.JobStatus.in_progress and not job.started_at:
        job.started_at = now
    if new_status == models.JobStatus.completed:
        job.completed_at = now
    if new_status == models.JobStatus.failed:
        job.failure_reason = payload.failure_reason or "Failed"

    db.add(job)
    write_audit(db, actor=user, action="job.status_change", target_type="job", target_id=job.id,
                details={"from": old.value, "to": new_status.value}, ip_address=get_client_ip(request))

    # Notify customer for some statuses
    customer = job.customer
    if customer and customer.user_id and new_status in (models.JobStatus.en_route, models.JobStatus.arrived, models.JobStatus.completed, models.JobStatus.cancelled, models.JobStatus.failed):
        notify(db, user_id=customer.user_id, title=f"Job {job.code} is now {new_status.value}", link=f"/portal/jobs/{job.id}")
    db.commit()
    db.refresh(job)
    enqueue_event(db, "job.status_changed", {"job_id": job.id, "code": job.code, "from": old.value, "to": new_status.value})
