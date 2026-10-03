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
# stub line 158
# stub line 159
# stub line 160
# stub line 161
    inc = db.query(models.Incident).filter(models.Incident.id == incident_id).one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Not found")
    if user.role not in (models.UserRole.ops_admin, models.UserRole.dispatcher):
        raise HTTPException(status_code=403, detail="Forbidden")
    if user.role == models.UserRole.dispatcher:
        if inc.job_id:
            job = db.query(models.Job).filter(models.Job.id == inc.job_id).one_or_none()
            if not job or job.region_id not in dispatcher_region_ids(db, user):
                raise HTTPException(status_code=403, detail="Forbidden")
        elif inc.reported_by_user_id != user.id:
            raise HTTPException(status_code=403, detail="Forbidden")

    changes: dict = {}
    if payload.severity is not None:
        changes["severity"] = {"from": inc.severity.value, "to": payload.severity.value}
        inc.severity = payload.severity
    if payload.status is not None and payload.status != inc.status:
        allowed = models.INCIDENT_STATUS_TRANSITIONS.get(inc.status, set())
        if payload.status not in allowed:
            raise HTTPException(status_code=400, detail=f"Invalid transition from {inc.status.value} to {payload.status.value}")
        changes["status"] = {"from": inc.status.value, "to": payload.status.value}
        inc.status = payload.status
        if payload.status == models.IncidentStatus.resolved and not inc.resolved_at:
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
        changes["assigned_to"] = inc.assigned_to_user_id
    if payload.internal_notes is not None:
        inc.internal_notes = payload.internal_notes
    if payload.customer_summary is not None:
        inc.customer_summary = payload.customer_summary
    db.add(inc)
    write_audit(db, actor=user, action="incident.update", target_type="incident", target_id=inc.id, details=changes, ip_address=get_client_ip(request))
    db.commit()
    db.refresh(inc)
    return _serialize(inc, user)
