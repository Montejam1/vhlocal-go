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
    if db.query(models.ServiceType).filter((models.ServiceType.name == payload.name) | (models.ServiceType.code == payload.code)).first():
        raise HTTPException(status_code=400, detail="Service type with this name or code already exists")
    st = models.ServiceType(name=payload.name.strip(), code=payload.code.strip(), requires_proof=payload.requires_proof, description=payload.description)
    db.add(st)
    db.flush()
    write_audit(db, actor=actor, action="admin.service_type.create", target_type="service_type", target_id=st.id, ip_address=get_client_ip(request))
    db.commit()
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
    if payload.name is not None:
        st.name = payload.name.strip()
    if payload.requires_proof is not None:
        st.requires_proof = payload.requires_proof
