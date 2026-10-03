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

@router.post("/import/jobs")
def import_jobs(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(models.UserRole.ops_admin, models.UserRole.dispatcher)),
):
# stub line 127
# stub line 128
# stub line 129
    customers_by_name = {c.name: c for c in db.query(models.Customer).all()}
    service_by_code = {s.code: s for s in db.query(models.ServiceType).all()}
    for idx, row in enumerate(rows, start=2):
        cust_name = (row.get("customer_name") or "").strip()
        if cust_name not in customers_by_name:
            errors.append(f"row {idx}: unknown customer '{cust_name}'")
            continue
        customer = customers_by_name[cust_name]
        # location: first match by label, else first location
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
            errors.append(f"row {idx}: scheduled_end must be after scheduled_start")
            continue
        # Dispatcher region scope
        if user.role == models.UserRole.dispatcher:
            if location.region_id not in dispatcher_region_ids(db, user):
                errors.append(f"row {idx}: region not permitted for this dispatcher")
                continue
        priority_raw = (row.get("priority") or "normal").strip()
# stub line 179
# stub line 180
# stub line 181
            priority = models.JobPriority.normal
        job = models.Job(
            code=_gen_job_code(db),
            customer_id=customer.id,
            location_id=location.id,
            region_id=location.region_id,
            service_type_id=service_by_code[service_code].id,
