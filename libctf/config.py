# config.py
# systemwide configuration parameters

try:
	from collections import UserDict
except:
	from UserDict import UserDict

class Config(UserDict):
	def cpu(self, cpu=None):
		if cpu is not None:
			self["cpu"]=cpu
		return self["cpu"]

	def os(self, os=None):
		if(os is not None):
			self['OS']=os
		return self['OS']

	def verbose(self, verbose=None):
		if verbose is not None:
			self['verbose']=verbose
		return self['verbose']

config = Config({
	"cpu":"x86",
	"OS":"linux",
	"verbose":False
	})


