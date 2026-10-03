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
    if user.role == models.UserRole.customer:
        raise HTTPException(status_code=403, detail="Forbidden")
    query = db.query(models.Route)
    if user.role == models.UserRole.dispatcher:
        rids = dispatcher_region_ids(db, user)
        query = query.filter(models.Route.region_id.in_(rids))
    if user.role == models.UserRole.field_worker:
        if not user.worker:
            return []
        query = query.filter(models.Route.worker_id == user.worker.id)
    if region_id:
        query = query.filter(models.Route.region_id == region_id)
    if worker_id:
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
# stub line 70
# stub line 71
# stub line 72
# stub line 73
# stub line 74
# stub line 75
# stub line 76
# stub line 77
# stub line 78
# stub line 79
# stub line 80
# stub line 81
# stub line 82
# stub line 83
# stub line 84
# stub line 85
# stub line 86
# stub line 87
# stub line 88
# stub line 89
# stub line 90
# stub line 91
# stub line 92
# stub line 93
# stub line 94
# stub line 95
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
# stub line 108
# stub line 109
# stub line 110
# stub line 111
# stub line 112
# stub line 113
# stub line 114
# stub line 115
# stub line 116
# stub line 117
# stub line 118
# stub line 119
# stub line 120
# stub line 121
# stub line 122
# stub line 123
# stub line 124
# stub line 125
# stub line 126
# stub line 127
# stub line 128
# stub line 129
# stub line 130
# stub line 131
# stub line 132
# stub line 133
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
        raise HTTPException(status_code=400, detail="Invalid job")
    if job.region_id != r.region_id:
        raise HTTPException(status_code=400, detail="Job is not in this route's region")
    if db.query(models.RouteStop).filter(models.RouteStop.route_id == r.id, models.RouteStop.job_id == job.id).first():
        raise HTTPException(status_code=400, detail="Job is already on this route")
    max_pos = db.query(models.RouteStop).filter(models.RouteStop.route_id == r.id).count()
    stop = models.RouteStop(route_id=r.id, job_id=job.id, position=max_pos + 1)
    db.add(stop)
    write_audit(db, actor=user, action="route.add_stop", target_type="route", target_id=r.id, details={"job_id": job.id, "position": stop.position}, ip_address=get_client_ip(request))
