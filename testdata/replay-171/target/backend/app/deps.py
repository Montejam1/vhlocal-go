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
def require_roles(*roles: models.UserRole):
    role_values = {r for r in roles}

    def _checker(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in role_values:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
        return user

    return _checker
# stub line 97
# stub line 98
# stub line 99
# stub line 100
# stub line 101
# stub line 102
# stub line 103
# stub line 104
def dispatcher_region_ids(db: Session, user: models.User) -> set[str]:
    rows = db.query(models.DispatcherRegion).filter(models.DispatcherRegion.user_id == user.id).all()
    return {r.region_id for r in rows}


def assert_dispatcher_can_access_region(db: Session, user: models.User, region_id: str) -> None:
    if user.role == models.UserRole.ops_admin:
        return
    if user.role != models.UserRole.dispatcher:
        raise HTTPException(status_code=403, detail="Forbidden")
    regions = dispatcher_region_ids(db, user)
    if not regions:
        # Dispatcher with no region assignments cannot manage any region.
        raise HTTPException(status_code=403, detail="Dispatcher has no permitted regions")
    if region_id not in regions:
        raise HTTPException(status_code=403, detail="Region not permitted")
