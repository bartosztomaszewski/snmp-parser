import re

def parser(mib_file):
	f = open(mib_file,"r")

	if f.mode is 'r':
		content = f.read()
	else:
		print("Operation on file is inappropriate")

	rfc1155 = (r'(IMPORTS|imports).+(FROM|from)\s(RFC1155|rfc1155)', content, re.M)
	if rfc1155:
		object = "1.3.6.1.2"
	else:
		print("This MIB file doesn't import structure from RFC1155")
		exit()

	mib_2 = re.search(r'mib-2.+::=.+mgmt\s(\d)', content) #creating OID 1.3.6.1.2.1
	if mib_2:
		object += "." + mib_2.group(1)
		mib_2_nod = tree_nod("mib-2",object)
	else:
		print("Didn't find MIB-2 nod")

	list_of_nods = []

	mib_2_structure = re.findall(r"^([a-zA-Z]+)\s+OBJECT\sIDENTIFIER.+mib-2\s+(\d+)", content, re.MULTILINE)

	if mib_2_structure:
		for x in range(len(mib_2_structure)):
			obj = tree_nod(mib_2_structure[x][0], mib_2_nod.OID + "." + mib_2_structure[x][1])
			list_of_nods.append(obj)
	else:
		print("Didn't find MIB-2's structure")

	list_of_leafs = []

	leafs = re.findall(r'([a-zA-Z0-9]+)\sOBJECT-TYPE$\s+SYNTAX\s+([^:]+)ACCESS\s+(.+)$\s+STATUS\s+(.+)$\s+DESCRIPTION$\s+\"([^\"]+)\"$\s+[^:]+::=\s+{\s+(\w+)\s(\d+)', content, re.MULTILINE)
	if leafs:
		for x in range(len(leafs)):

			leaf_OID = "empty"

			for y in range(len(list_of_nods)):
				if leafs[x][5] == list_of_nods[y].Name:
					leaf_OID = list_of_nods[y].OID
			if leaf_OID == "empty":
				for z in range(len(list_of_leafs)):
					if leafs[x][5] == list_of_leafs[z].Name:
						leaf_OID = list_of_leafs[z].OID

			obj = tree_leaf(leafs[x][0], leaf_OID + "." + leafs[x][6], leafs[x][1], leafs[x][2], leafs[x][3], leafs[x][4])
			list_of_leafs.append(obj)
	else:
		print("Didn't find any leafs")

	#menu
	print("You have created MIB tree from RFC1213 file - what do you want to do next?\n1 - Show whole tree\n2 - Find specific object by OID\n3 - Find specific object by name\nq - exit program")
	flag = 0
	
	while flag != 1:
		option = input()
		try:
			if int(option) <= 3:
				option = int(option)
				flag = 1
				if option is 1:
					print(mib_2_nod.OID + " -> " + mib_2_nod.Name)
					for x in range(len(list_of_nods)):
						print(list_of_nods[x].OID + " -> " + list_of_nods[x].Name)
						for y in range(len(list_of_leafs)):
							if (list_of_nods[x].OID + ".") in list_of_leafs[y].OID:
								print(list_of_leafs[y].OID + " -> " + list_of_leafs[y].Name)

				elif option == 2:
					print("Write OID in format \"digit dot digit ...\" e.g \"1.2.3.4.5\" :")
					my_OID = input()
					for x in range(len(list_of_nods)):
						if list_of_nods[x].OID == my_OID:
							print("\nName -> " + list_of_nods[x].Name + "\nOID -> " + list_of_nods[x].OID)# + "\nSyntax -> " + list_of_nods[x].Syntax + "\nAccess -> " + list_of_nods[x].Access + "\nStatus -> " + list_of_nods[x].Status + "\nDescription -> " + list_of_nods[x].Descr)
							exit(0)
					
					for y in range(len(list_of_leafs)):
						if list_of_leafs[y].OID == my_OID:
							print("\nName -> " + list_of_leafs[y].Name + "\nOID -> " + list_of_leafs[y].OID + "\nSyntax -> " + list_of_leafs[y].Syntax + "\nAccess -> " + list_of_leafs[y].Access + "\nStatus -> " + list_of_leafs[y].Status + "\nDescription -> " + list_of_leafs[y].Descr)
							exit(0)

					print("Sadly your OID doesn't match")

				else:
					print("Write name (it isn't case sensitive):")
					my_name = input()
					my_name = my_name.lower()
					
					for x in range(len(list_of_nods)):
						lowercase_name = list_of_nods[x].Name
						if lowercase_name == my_name:
							print("\nName -> " + list_of_nods[x].Name + "\nOID -> " + list_of_nods[x].OID)# + "\nSyntax -> " + list_of_nods[x].Syntax + "\nAccess -> " + list_of_nods[x].Access + "\nStatus -> " + list_of_nods[x].Status + "\nDescription -> " + list_of_nods[x].Descr)
							exit(0)

					for y in range(len(list_of_leafs)):
						lowercase_name = list_of_leafs[y].Name.lower()
						#print(lowercase_name + " == " + my_name)
						if lowercase_name == my_name:
							print("\nName -> " + list_of_leafs[y].Name + "\nOID -> " + list_of_leafs[y].OID + "\nSyntax -> " + list_of_leafs[y].Syntax + "\nAccess -> " + list_of_leafs[y].Access + "\nStatus -> " + list_of_leafs[y].Status + "\nDescription -> " + list_of_leafs[y].Descr)
							exit(0)

					print("Sadly your Name doesn't match")

			else:
					print("You gave the wrong digit :( Try one more time:")
		except ValueError:
			if option == "q" or option == "Q":
				exit(0)
				#quit()
			else:
				print("You gave a letter instead of digit. Try one more time:")
	return

class tree_leaf:
	def __init__(self, name, oid, syntax, access, status, descr):
		self.Name = name
		self.OID = oid
		self.Syntax = syntax
		self.Access = access
		self.Status = status
		self.Descr = descr

class tree_nod:
	def __init__(self, name, oid):
		self.Name = name
		self.OID = oid

if __name__ == "__main__":
	parser("RFC1213-MIB.txt")
