MD5Values = [ '"d7 6a a4 78"', '"e8 c7 b7 56"', '"24 20 70 db"', '"c1 bd ce ee"' ]
min,max = MinEA(),MaxEA()
MD5Present = False
print "Checking for MD5 constants..."

for MD5 in MD5Values:
	#Search for the MD5 values throughout the program, starting from the program's minimum EA
	addr = FindBinary(min,SEARCH_DOWN,MD5,16)
	if (min <= addr <= max):
		print addr
		MD5Present = True

if MD5Present:
	print "MD5 Constants present"
else
	print "MD5 Constants not detected"
