
class PermissionCheck:
    @classmethod
    def check(cls, requirement, permissions):
        if permissions == None:
            return False
        if isinstance(requirement, str):
            return set(requirement).issubset(set(permissions))
        elif isinstance(requirement, PermissionCheck):
            return requirement.match(permissions)
            
    @classmethod
    def checkIncludesAdmin(cls, requirement):
        if isinstance(requirement, str):
            return not requirement.islower()
        elif isinstance(requirement, PermissionCheck):
            return requirement.hasAdmin()
        return False
    
    def match(self, permissions):
        return False
        
    def hasAdmin(self):
        return False
        
    def __str__(self):
        return ""

class PermissionsSet(PermissionCheck):
    def __init__(self, *permissions):
        self._permissions = permissions
        
    def __str__(self):
        return " or ".join([str(p) for p in self._permissions])
        
    def match(self, x):
        for p in self._permissions:
            if PermissionCheck.check(p, x):
                return True
        return False
        
    def hasAdmin(self):
        for p in self._permissions:
            if PermissionCheck.checkIncludesAdmin(p):
                return True
        return False
        
class PermissionsExist(PermissionCheck):
    def __init__(self, admin=False):
        self._admin = admin
    def match(self, x):
        # if not admin, we are looking for at least one lower case letter
        if not self._admin:
            if len(x) > 0 and not x.isupper():
                return True
        else:
            # we allow any admin privileges as well
            if len(x) > 0:
                return True
        return False
    def hasAdmin(self):
        return self._admin
    def __str__(self):
        return "any permissions"