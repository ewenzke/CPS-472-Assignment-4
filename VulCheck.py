vulnerableFunctions = [ 'strcpy', 'sprintf', 'strncpy', 'wcsncpy', 'swprintf' ]
min,max = MinEA(), MaxEA()
functionList = Functions(min,max)
print 'AAAAAAUUUUGHHHH'

							

def handle_function( function ):
	for head in Heads(function, SegEnd(function)):
		if isCode(GetFlags(head)):
			mnem = GetMnem(head)
			if mnem == "call":				
				for s in vulnerableFunctions:
					if s in GetDisasm(head):
						print '%s:%08x:%s %s' % (GetFunctionName(f), head, GetOpnd(head, 0), GetOpnd(head,1))

							

							
for f in functionList:
	handle_function(f)