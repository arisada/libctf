# langutils.py
# contains several language tricks to make python better

import bisect
# http://code.activestate.com/recipes/410692/
# This class provides the functionality we want. You only need to look at
# this if you want to know how this works. It only needs to be defined
# once, no need to muck around with its internals.
class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration
    
    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args: # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False

class MaxSortedList(object):
    """Implementation of a list where elements are kept sorted, and only the
    maxn biggest elements are kept"""
    def __init__(self, maxn):
        self._maxn = maxn
        self._list = []
    def append(self, e):
        self._list.reverse()
        bisect.insort(self._list, e)
        self._list.reverse()
        if len(self._list) > self._maxn:
            del self._list[-1]
    def __eq__(self, e):
        return self._list == e
    def __getitem__(self, e):
        return self._list[e]
    def __len__(self):
        return len(self._list)
    def __str__(self):
        return str(self._list)

class NamedDict(dict):
    """Dictionary whose values can be accessed with dictobject.key"""
    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError(name)
    def __setattr__(self, name, value):
        if name in self:
            self[name]=value
        else:
            raise AttributeError(name)
