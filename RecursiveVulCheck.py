vulnerableFunctions = [ 'strcpy', 'sprintf', 'strncpy', 'wcsncpy', 'swprintf' ]
min,max = MinEA(), MaxEA()
functionList = Functions(min,max)
functionsChecked = dict.fromkeys(functionList)
print 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUUUUGHHHH'

def handle_function( function ):
	functionsChecked[function] = 1
	for head in Heads(function, SegEnd(function)):
		if isCode(GetFlags(head)):
			mnem = GetMnem(head)
			if mnem == "call":
				references = XrefsFrom(head, 0)			
				for xref in references:
					if GetFunctionName(xref.to) in functionsChecked is 0:
						handle_function(xref.to)
					else:
						functionsChecked[GetFunctionName(xref.to)] = 1
				for s in vulnerableFunctions:
					if s in GetDisasm(head):
						print '%s:%08x:%s %s' % (GetFunctionName(f), head, GetOpnd(head, 0), GetOpnd(head,1))	

for f in functionList:
#	print 'Entering function %s' % GetFunctionName(f)
	handle_function(f)
	
#for function in functionsChecked:
#	print function