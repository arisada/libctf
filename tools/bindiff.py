#!/usr/bin/env python

from libctf import bindiff, bindifftable, cencode
import sys
import argparse

template = """#!/usr/bin/env python

f = open("$IN").read()
patches = $TABLE
for p in patches:
	if f[p[0]:p[0] + len(p[1])] != p[1]:
		print "Original data invalid. Already patched ?"
		if f[p[0]:p[0] + len(p[1])] == p[2]:
			print "Yes."
		else:
			print "No."
	else:
		f = f[:p[0]] + p[2] + f[p[0] + len(p[2]):]
patched = open("$OUT","w")
patched.write(f)
"""

def create_patch(file1, file2, outfile):
	d1=open(file1).read()
	d2=open(file2).read()
	table = bindifftable(d1, d2)
	if len(table)==0:
		print "Files are identical !"
		return
	stable = "[\n"
	for a,b,c in table:
		stable += '\t(%d,%s,%s),\n'%(a, cencode(b), cencode(c))
	stable += "]\n"
	patch = template.replace("$IN", file1).replace("$OUT", file2)
	patch = patch.replace("$TABLE", stable)
	open(outfile,"w").write(patch)
	print "written patch file %s, %d diffs"%(outfile, len(table))

def main():
	parser = argparse.ArgumentParser(description="Diffing two binary files")
	parser.add_argument('-p', help='Create patch', metavar="patch.py")
	parser.add_argument('orig', nargs=1, metavar="orig")
	parser.add_argument('tocompare', nargs=1, metavar='tocompare')
	args = parser.parse_args()
	if args.p != None:
		create_patch(args.orig[0], args.tocompare[0], args.p)
	else:
		d1=open(args.orig[0]).read()
		d2=open(args.tocompare[0]).read()
		bindiff(d1, d2)
	

if __name__ == '__main__':
	main()