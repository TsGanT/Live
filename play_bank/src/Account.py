'''
Created on Mar 24, 2014

@author: sethjn
'''

class Account(object):
    def __init__(self):
        self.__bitPoints = set([])
    
    def balance(self):
        return len(self.__bitPoints)
    
    def deposit(self, bitPoints):
        newSet = set(bitPoints)
        if not self.__bitPoints.isdisjoint(newSet):
            raise Exception("Duplicate bitpoint detected!")
        self.__bitPoints.update(newSet)
        
    def withdraw(self, amount):
        if amount > self.balance():
            return None
        bitPointSet = []
        
        # Hope this doesn't take too long...
        while len(bitPointSet) < amount:
            bitPointSet.append(self.__bitPoints.pop())