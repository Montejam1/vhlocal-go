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
    if user.role == models.UserRole.customer:
        # Customer only sees themselves
        if not user.customer:
            return []
        return [user.customer]
    query = db.query(models.Customer)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(or_(models.Customer.name.ilike(like), models.Customer.contact_email.ilike(like)))
    return query.order_by(models.Customer.name.asc()).offset(offset).limit(limit).all()
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

@router.delete("/{customer_id}", status_code=204)
def delete_customer(
    customer_id: str,
    request: Request,
    db: Session = Depends(get_db),
    actor: models.User = Depends(require_roles(models.UserRole.ops_admin)),
):
    c = db.query(models.Customer).filter(models.Customer.id == customer_id).one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Not found")
    if db.query(models.Job).filter(models.Job.customer_id == customer_id).first():
        raise HTTPException(status_code=400, detail="Customer has jobs and cannot be deleted")
    db.delete(c)
    write_audit(db, actor=actor, action="customer.delete", target_type="customer", target_id=customer_id, ip_address=get_client_ip(request))
    db.commit()
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
    c = db.query(models.Customer).filter(models.Customer.id == customer_id).one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Customer not found")
    region = db.query(models.Region).filter(models.Region.id == payload.region_id).one_or_none()
    if not region:
        raise HTTPException(status_code=400, detail="Invalid region_id")
    loc = models.ServiceLocation(
        customer_id=customer_id,
        region_id=payload.region_id,
        label=payload.label.strip(),
# stub line 159
# stub line 160
# stub line 161
# stub line 162
# stub line 163
# stub line 164
        latitude=payload.latitude,
        longitude=payload.longitude,
        notes=payload.notes,
    )
    db.add(loc)
    db.flush()
    write_audit(db, actor=actor, action="customer.location.create", target_type="service_location", target_id=loc.id, ip_address=get_client_ip(request))
    db.commit()
    db.refresh(loc)
    return loc
