import sys
import pefile  
import getopt 

print('''
 __       ___   .___________.        ___      .__   __.      ___       __      ____    ____  ________   _______ .______      
|  |     /   \  |           |       /   \     |  \ |  |     /   \     |  |     \   \  /   / |       /  |   ____||   _  \     
|  |    /  ^  \ `---|  |----`      /  ^  \    |   \|  |    /  ^  \    |  |      \   \/   /  `---/  /   |  |__   |  |_)  |    
|  |   /  /_\  \    |  |          /  /_\  \   |  . `  |   /  /_\  \   |  |       \_    _/      /  /    |   __|  |      /     
|  |  /  _____  \   |  |         /  _____  \  |  |\   |  /  _____  \  |  `----.    |  |       /  /----.|  |____ |  |\  \--.
|__| /__/     \__\  |__|        /__/     \__\ |__| \__| /__/     \__\ |_______|    |__|      /________||_______|| _| `.___|
                                                                                                                              ''')

				 
print("\nWELCOME TO IMPORT ADDRESS TABLE (IAT) ANALYZER.")


file = ''

try:                                
	opts, args = getopt.getopt(sys.argv[1:],"hi:",["help","ifile"])
except getopt.GetoptError as e:
	print("iat.py -i <file>")
	sys.exit(2)
for opt, arg in opts:
	if opt in ("-h", "--help"):
		print("iat.py -i <file>")
		sys.exit()
	elif opt in ("-i", "--ifile"):
		file = arg
		pe =  pefile.PE(file)
		
		print(f"\nFile is opening -> {file}\n---Listing imported DLLs, Module Name, Virtual Address---\n")
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dllname = entry.dll.decode("utf-8")
			print(f"{dllname} imports :")
			for func in entry.imports:
				print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))


			
	

        
        
        
   


