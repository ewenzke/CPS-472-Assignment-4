vulnerableFunctions = [ 'strcpy', 'sprintf', 'strncpy', 'wcsncpy', 'swprintf' ]
min,max = MinEA(), MaxEA()

#Construct a dictionary from the list of functions, with arbitrary values
functionList = Functions(min,max)
functionsChecked = dict.fromkeys(functionList)

#Delimiter to separate consecutive runs
#Also this assignment was frustrating
print 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUUUUGHHHH'


def handle_function( function ):
	#Flag this function as searched
	functionsChecked[function] = 1
	#Search each line in the segment. If it is code, find the lines with the mnemonic 'call'
	for head in Heads(function, SegEnd(function)):
		if isCode(GetFlags(head)):
			mnem = GetMnem(head)
			if mnem == "call":
				#Find the functions these lines reference, and add them to the search, recursively
				references = XrefsFrom(head, 0)			
				for xref in references:
					#Here is where there is probably a problem. If the key's value in the dict is 0, it has not
					#been searched, and we call handle_function again. However, if it is not present, we enter 
					#the else statement. Trying to get Python to do this has been maddening. 
					#Adding an 'or not functionsChecked[GetFunctionName(xref.to)]' cause recursive crash.
					#Adding 'elif GetGunctionName(xref.to) not in functionsChecked' causes the same occurances of
					#the vulnerable methods to be searched and presented.
					if GetFunctionName(xref.to) in functionsChecked is 0:
						handle_function(xref.to) 
					elif GetFunctionName(xref.to) not in functionsChecked:
						functionsChecked[GetFunctionName(xref.to)] = 1
						handle function(xref.to)
					else:
						functionsChecked[GetFunctionName(xref.to)] = 1
				#Search the 'call' lines for occurances of the vulnerable methods, if found, print the name of the callee,
				#the address, and the operand
				for s in vulnerableFunctions:
					if s in GetDisasm(head):
						print '%s:%08x:%s %s' % (GetFunctionName(f), head, GetOpnd(head, 0), GetOpnd(head,1))	

#Iterate over all the initial functions on the list
for f in functionList:
#	print 'Entering function %s' % GetFunctionName(f)
	handle_function(f)
	
#Debug: print the list of keys for the Function dict
#for function in functionsChecked:
#	print function
