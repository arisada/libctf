# config.py
# systemwide configuration parameters

config = {
	"cpu":"x86",
	"OS":"linux",
	"verbose":False
}

def cpu(cpu=None):
	if cpu is not None:
		config["cpu"]=cpu
	return config["cpu"]

def os(os=None):
	if(os is not None):
		config['OS']=os
	return config['OS']

def verbose(verbose=None):
	if verbose is not None:
		config['verbose']=verbose
	return config['verbose']
