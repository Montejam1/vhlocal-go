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
):
    region = db.query(models.Region).filter(models.Region.id == region_id).one_or_none()
    if not region:
        raise HTTPException(status_code=404, detail="Not found")
    # Prevent delete if in use by jobs or locations
    in_use_job = db.query(models.Job).filter(models.Job.region_id == region_id).first()
    in_use_loc = db.query(models.ServiceLocation).filter(models.ServiceLocation.region_id == region_id).first()
    if in_use_job or in_use_loc:
        raise HTTPException(status_code=400, detail="Region is in use")
    db.delete(region)
    write_audit(db, actor=actor, action="admin.region.delete", target_type="region", target_id=region_id, ip_address=get_client_ip(request))
    db.commit()
    return None
