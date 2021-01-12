import sys
import socket
import time
import datetime
from geopy.geocoders import Nominatim
import requests
from bs4 import BeautifulSoup




def getHostList(ip_list):
	"""
	@param
	- ip_list : str => file name as a string (file must contain one IP by line)
	@description
	- Reads the file containing IP adresses and give each IP to getHost() function.
	  Writes the result of the function in a text file in the format : IP;hostname or IP;HostUnknown
	@return
	- 0 when done reading all the IPs in the file
	"""
	f = open(ip_list, "r")
	out = open("netmetIPhostList.txt", "w")
	
	lines = f.readlines()
	f.close()
	
	for i in lines:
		cmd_out = getHost(i[:-1])
		if(not cmd_out):
			out.write(i[:-1]+";HostUnknown"+"\n")
		else:
			out.write(i[:-1]+";"+getHost(i[:-1])[1:-1]+"\n")
	out.close()
	return 0




def getHost(ip):
	"""
	@param
	- ip : str => ip as a string
	@description
	- This method returns the 'True Host' name for a given IP address
	@return
	- Hostname if host is found, False else
	"""
	try:
		data = socket.gethostbyaddr(ip)
		host = repr(data[0])
		return host
	except Exception as e:
		# fail gracefully
		print(e)
		return False




def readHostName(ip_host_file, write_log):
	"""
	@param
	- ip_host_file : str => file name as string
	- write_log : boolean => used to select if terminal output is writtent to txt file
	@description
	- Reads the file containing <IP;hostname> and extract the hostname for further analysis. Can write output to txt file
	@return
	- Nothing
	"""
	f = open(ip_host_file, "r")
	Lines = f.readlines()
	f.close()
	if(write_log):
		dt = str(datetime.datetime.now()).split( )[0]	
		out = open("GeoIP"+dt+".txt", "w", buffering=1, encoding="utf-8")

	# load country cities dict
	CC = loadCityDict("CountryCities.txt")
	A2 = loadCountryCodes("CountryCodes.txt")
	# stat counter
	unknown_host = 0
	unknown_location = 0
	insufficient_location_info = 0
	tt = 0
	for line in Lines:
		line_splited = line.split(';')
		ip = line_splited[0]
		host_name = line_splited[1]
		if("HostUnknown" not in host_name):
			# if there is a host name then we can analyze it
			host_name = host_name[:-1]
			res = deepAnalyze2(host_name, A2)
			if(res != {}):
				for key in res:
					if(res[key] >= 75.0):
						location = geoCoding(A2[key])
						score = verifyAdressWithAPI(ip, location)
						if(write_log):
							to_write = f"IP:[{ip}], HostName:[{host_name}], Guessed in {A2[key]} at [{location[0], location[1]}], API verification:[{score}]\n"
							out.write(to_write)
						print(f"IP:[{ip}], HostName:[{host_name}], Guessed in {A2[key]} at [{location[0], location[1]}], API verification:[{score}]")
					else:
						insufficient_location_info +=1
						if(write_log):
							to_write = f"IP:[{ip}], HostName:[{host_name}], Guessed in {A2[key]} => INSUFFICIENT ACCURACY : Only {res[key]}% probability]\n"
							out.write(to_write)
						print(f"IP:[{ip}], HostName:[{host_name}], Guessed in {A2[key]} => INSUFFICIENT ACCURACY : Only {res[key]}% probability]")
			else:
				if(write_log):
					to_write = f"IP:[{ip}], HostName:[{host_name}], Guessed at [UNKNOWN]\n"
					out.write(to_write)
				print(f"IP:[{ip}], HostName:[{host_name}], Guessed at [UNKNOWN]")
				unknown_location += 1
		else:
			out.write(f"IP:[{ip}], HostName:[UNKNOWN], Guessed at [UNKNOWN]\n")
			unknown_host += 1
		tt += 1
	print((f"\n###########################################################\nTotal IP location found : {tt-unknown_host-unknown_location}\nTotal host not responding : {unknown_host}\nTotal location not found : {unknown_location} including {insufficient_location_info} with insufficient location information\n###########################################################"))
	if(write_log):
		out.write(f"\n###########################################################\nTotal IP location found : {tt-unknown_host-unknown_location}\nTotal host not responding : {unknown_host}\nTotal location not found : {unknown_location} including {insufficient_location_info} with insufficient location information\n###########################################################")
		out.close()




def deepAnalyze2(host_name, country_code_dict):
	"""
	@param
	- host_name : str
	- country_code_dict : {str:str}
	@description
	- Analyzes a host name to find country code and country names in the string
	  Returns the results in a dict as {str_country_code:float_accuracy_scale}
	@return
	- The new dictionary
	"""
	res = dict()
	host_splited = host_name.split('.')
	CC = loadCityDict("CountryCities.txt")
	current_CC = ""
	for word in host_splited:
		if(containsNumerics(word)):
			continue
		if(len(word) == 2):
			maybe_country = matchCountryCode(res, word, country_code_dict)
			if(maybe_country != -1 and maybe_country != ""):
				current_CC = maybe_country
		if(len(word) > 2):
			matchCountryName(res, word, country_code_dict)
			#matchCityName(res, CC, word, A2)
	return res




def deepAnalyze(host_name):
	"""
	@param
	- host_name : str => host name as a string
	@description
	- Realize a deep analyze of the host name at different levels
	@return
	- The most probable geographic location
	"""
	res = dict()
	host_splited = host_name.split('.')
	CC = loadCityDict("CountryCities.txt")
	alpha2 = loadCountryCodes("CountryCodes.txt")
	alpha2_keys = list(alpha2.keys())
	current_CC = "" # current country code
	for word in host_splited:
		if(containsNumerics(word)):
			continue
		if('-' in word):
		# case where word is subdivised by '-'
			word_splited = word.split('-')
			for sub_word in word_splited:
				sub_word_UP = sub_word.upper()
				# search in alpha2 dict
				if(sub_word_UP in alpha2_keys):
					current_CC = sub_word_UP
					if(sub_word_UP in res.keys()):
						res[alpha2[sub_word_UP]] += 0.01
					else:
						res[alpha2[sub_word_UP]] = 0.01
		else:
		# case where word isn't subdivised
			word_UP = word.upper()
			if(word_UP in alpha2_keys):
				current_CC = word_UP
				if(word_UP in res.keys()):
					res[alpha2[word_UP]] += 1
				else:
					res[alpha2[word_UP]] = 1
		if(current_CC != ''):
		#	print(current_CC)
		#	res = findCityInHost(CC, word, current_CC, res)
			res = findCityInHost(CC, host_name, current_CC, res)
	return res




def matchCityName(input_dict, CC_dict, host_name, country_code):
	"""
	@param
	- input_dict : {str:float} => the dictionary of matching score where str = country or city name and float is our accuracy scale higher is better
	- CC_dict : {str:[str,str,...]} => dictionary of cities for each country
	- host_name : str => a hostname given by the DNS reverse request
	- country_code : str => a 2 letter country code
	@description
	- Creates a dictionary containing the matching city names
	  The accuracy scale works as follow : add 1 if country code match, add 0.01 if city name complete match, add 0.0001 if matching only few letters from a city name
	@return
	- The dictionnary of matching city names updated with the new matchs
	"""
	host_splited = host_name.split('.')
	for word in host_splited:
		if(containsNumerics(word)):
			continue
		else:
			word_formated = word[0].upper()+word[1:]
			for city in CC_dict[country_code]:
				if(len(word_formated) > len(city)):
					# word in host name longer than city name
					if(city in word_formated):
						if(city not in input_dict.keys()):
							input_dict[city] = 1
						else:
							input_dict[city] += 1
				else:
					if(len(word_formated) > 2):
						# word in host name shorter than city name
						if(word_formated in city):
							if(city not in input_dict.keys()):
								input_dict[city] = 0.01
							else:
								input_dict[city] += 0.01
					elif(len(word_formated) == 2 and word_formated.upper() != country_code):
						# word len = 2
						city_concat = city[0]+city[-1]
						if(word_formated in city_concat):
							if(city not in input_dict.keys()):
								input_dict[city] = 0.0001
							else:
								input_dict[city] += 0.0001
	return input_dict




def matchCountryCode(input_dict, host_name_part, country_code_dict):
	"""
	@param
	- input_dict : {str:float} => main matching dictionary with country code associated with score
	- host_name_part : str => a part of the host name to analyze
	- country_code_dict : {str:str} => dictionary of country code associated with country name
	@description
	- Finds if a country code is matching the host_name_part, if yes then adds it to input_dict
	@return
	- The matching country code or empty if no match
	"""
	if(len(host_name_part) > 2):
		return -1
	for code in country_code_dict:
		if(code == host_name_part.upper()):
			if(code not in input_dict.keys()):
				input_dict[code] = 100
			else:
				input_dict[code] += 100
			return code
	return ""




def matchCountryName(input_dict, host_name_part, country_code_dict):
	"""
	@param
	- input_dict : {str:float} => main matching dictionary with country code associated with score
	- host_name_part : string
	- country_code_dict : {str:float}
	@description
	- Find if a country name match at least 3 letter of a country name return a dict {country_name:matched_score}
	  matched_score is calculated based on how many letters are matched in the hole host_name_part (in %)
	@return
	- The input dictionary
	"""
	res = {}
	for code in country_code_dict:
		country_name = country_code_dict[code].lower()
		country_name_concat = ""
		still_matching = 0
		matched_letters = 0
		for i in range(len(country_name)):
			if(still_matching != i):
				break
			country_name_concat += country_name[i]
			if(country_name_concat in host_name_part):
				matched_letters += 1
				still_matching += 1
		accuracy = matched_letters / len(host_name_part) * 100 
		if(accuracy > 25.0 and matched_letters > 3):
			res[code] = accuracy
	sorted_list = sorted(res.items(), key=lambda x:x[1], reverse=True)
	if(len(sorted_list) > 0):
		more_probable = sorted_list[0]
		if(more_probable[0] not in input_dict.keys()):
			input_dict[more_probable[0]] = more_probable[1]
		else:
			input_dict[more_probable[0]] += more_probable[1]
	return input_dict




#=======================================================================================================================================
# TOOL BOX
def loadCountryCodes(file_name):
	"""
	@param
	- file_name : str => file containing the country codes/country name
	@description
	- Loads the country code as a dictionaries => {country_code_alpha2: country_name}
	@return
	- The newly created dictionary
	"""
	base_alpha2 = dict()
	f = open(file_name, "r", encoding='utf-8')
	Lines = f.readlines()
	for line in Lines[1:]:
		line_splited = line.split(';')
		#print(f"LS0 [{line_splited[0]}], LS1 [{line_splited[1][:-1]}]")
		base_alpha2[line_splited[0]] = line_splited[1][:-1]
	return base_alpha2




def geoCoding(adrs):
    """
    @param
    - adrs : string => location adress as city or country name
    @description
    - Does a GPS search to find a possible GPS position associated with the input string
    @return
    - Location as tuple of (latitude, longitude)
    """
    geolocator = Nominatim(user_agent="api")
    location = None
    try_cpt = 0
    while(location == None and try_cpt < 20):
        location = geolocator.geocode(adrs)
        try_cpt += 1
    #print(f"Found '{adrs}' in {try_cpt} try, located at : [{location.latitude}, {location.longitude}]")
    return (location.latitude, location.longitude)




def getCityByCountry(country_code_dict):
	"""
	@param
	- country_code_dict : {str_code : str_name}
	@description
	- Creates a big dictionary containing for each country code most of it's cities as {str_code : [str_city,str_city,...]}
	@return
	- The newly created dictionary
	"""
	country_cities = dict()
	url = "https://service.unece.org/trade/locode/"
	for country_code in country_code_dict.keys():
		print("Scraping cities from : ", country_code_dict[country_code])
		country_cities[country_code] = getCityFromHTML(url+country_code.lower()+".htm")
		time.sleep(5)
	return country_cities




def getWriteCityByCountryByChunks(country_code_dict, output_file):
	"""
	@param
	- country_code_dict : {str_code : str_name}
	- output_file : str => the file to save the data in
	@description
	- Writes country code folowed by most of it's cities as str_code;str_city;str_city;...
	  The function writes a log file containing only one line with country code separated by a space.
	  The country code is written when all the cities of the country have been found.
	  We need the log file because the web page only allow a few data before resetting the connection so basically we retrieve as much data as possible before the connection is reset.
	  Files are openned in "a" append mode to add at the end of them.
	@return
	- A list of cities of a country
	"""
	# reading exixting log
	log = open("log.txt", "r", encoding="utf-8")
	country_done = log.read().split( )
	log.close()
	# writing log
	log = open("log.txt", "a", buffering=1, encoding="utf-8")
	out = open(output_file, "a", encoding="utf-8")
	url = "https://service.unece.org/trade/locode/"
	country_code_list = [e for e in country_code_dict.keys() if e not in country_done]
	for country_code in country_code_list: #_dict.keys():
		print("Scraping cities from : ", country_code_dict[country_code])
		country_cities = getCityFromHTML(url+country_code.lower()+".htm")
		out.write(country_code+";"+listToWritableCSV(country_cities))
		log.write(country_code+" ")
		time.sleep(5)
	out.close()
	return country_cities




def getCityFromHTML(url):
	"""
	@param
	- url : str => url pointing to a webpage
	@description
	- Finds most of the cities of all the country and creates a list of city names of a country as [str_city,str_city,...]
	@return
	- The created list
	"""
	page = requests.get(url)
	soup = BeautifulSoup(page.content, "html.parser")
	cities = []
	td = soup.find_all("td")
	cpt = 0
	round = 0
	for line in td:
		line_s = str(line).replace('"', '')
		if("<td height=1 valign=Top width=19%>" in line_s):
			city_name = line.get_text()[:-1]
			cpt += 1
			if(cpt == 2):
				# appends the second which doesnt contain any accent => simpler to match in the futur
				cities.append(city_name)
				cpt = 0
	return cities




def listToWritableCSV(input_list):
	"""
	@param
	- input_list : str => the input list to return as writable
	@description
	- Creates a single string from the input list separated by ';'
	@return
	- The newly created string
	"""
	if(len(input_list) == 0):
		return "\n"
	elif(len(input_list) == 1):
		return input_list[0]+"\n"
	else:
		list_concat = ""
		for element in input_list:
			list_concat += element+";"
		return list_concat[:-1]+"\n"




def containsNumerics(input_str):
	"""
	@param
	- input_str : str => the string to check
	@description
	- Checks if input string contains any number
	@return
	- True if it contains at least one number, False if none
	"""
	numerics = "0123456789"
	for number in numerics:
		if number in input_str:
			return True
	return False




def writeDictCSV(src_dict, output_filename):
	"""
	@param
	- src_dict : {key:value} => the source dictionary to write
	- output_filename : str => name of the file where the dictionary will be written
	@description
	- Writes a python dictionary into a file in CSV format
	@return
	- Nothing for now
	"""
	f=open(output_filename, "w", encoding='utf-8')
	for key in src_dict.keys():
		f.write(key)
		if(type(src_dict[key]) == list):
			for n in src_dict[key]:
				f.write(";"+n)
		else:
			f.write(";"+src_dict[key])
		f.write("\n")
	f.close()
	return 0




def loadCityDict(src_file):
	"""
	@param
	- src_dict : {str:[str,str,str,...]}
	@description
	- Creates a dictionary from a txt file
	@return
	- The created dictionary
	"""
	country_cities = dict()
	f = open(src_file, "r", encoding="utf-8")
	for line in f:
		line_splited = line.split(';')
		country_code = line_splited[0]
		country_cities[country_code] = []
		for city in line_splited[1:]:
			if('\n' in city):
				city = city[:-1]
			country_cities[country_code].append(city)
	return country_cities




def verifyAdressWithAPI(ip_address, location):
	"""
	@param
	- ip_address : str => an ip address to verify
	- location : (str,str) => a location associated with the IP address to verify
	@description
	- Post a request to the Planet-Lab's verification API and return the response
	@return
	- The response of the request
	"""
	url="http://ares.planet-lab.eu:8000"
	data = {ip_address:[location[0], location[1]]}
	response = requests.post(url, json=data)
	for line in response:
		line = str(line[4:-3])[2:-1]
		line = line.replace('"', '')
	return line




if __name__ == '__main__':
	print(sys.version)
	#getHostList("netmetIPlist.txt")
	#a2 = loadCountryCodes("countryCode.txt")
	#print(deepAnalyze("p5483cdfd.dip0.t-ipconnect.de"))
	#print(deepAnalyze("atlas-probe-01.dasburo.com"))
	#print(deepAnalyze("intermax-ripeatlas-61.intermax.nl"))
	#print(deepAnalyze("cust-zlinnet-2.supernetwork.cz"))
	#print(deepAnalyze("mariner.static.otenet.gr"))
	#print(deepAnalyze(""))
	#print(a2)
	#print(a3)
	#print(a2['NP'])
	#getHostList("netmetIPlist.txt")
	#readHostName("netmetIPhost.txt")
	#geoCoding("Brazil")
	#print(containsNumerics("Acoute-villier"))
	#print(containsNumerics("Acoute-Vidas 4564 89"))
	#getCityFromHTML("https://service.unece.org/trade/locode/fr.htm")
	# https://unece.org/cefact/unlocode-code-list-country-and-territory
	#print(a2)
	#a2 = loadCountryCodes("countryData.txt")
	#writeDictCSV(a2, "CountryCodes.txt")
	#a = {"AF":["aa", "bbb", "ccc"], "FR":["ddd", "eee", "fff"]}
	#writeDictCSV(a, "TEMP.txt")
	#writeDictCSV(cCities, "CountryCIties.txt")
	#print(listToWritableCSV(['zzz', 'dhzqjkd']))
	#a2 = loadCountryCodes("countryData.txt")
	#cCities = getWriteCityByCountryByChunks(a2, "CountryCities.txt")
	#CC = loadCityDict("CountryCities.txt")
	#print(CC['CZ'])
	#print(findCityInHost(CC, "host-195-16-81-5.leipziger-messe.de", "DE"))
	#print(findCityInHost(CC, "atlas-anchors.nic.cz", "CZ"))
	#print(findCityInHost(CC, "pcisrv.consultik.qc.ca", "CA"))
	#verifyAdressWithAPI("195.16.81.5", (-50.4,32.78))
	#print(deepAnalyze("ripe-atlas-anchor.franceix.net"))
	#readHostName("netmetIPhost.txt", True)
	#A2 = loadCountryCodes("CountryCodes.txt")
	#print(matchCountryName({}, "franceix", A2))
	#print(matchCountryCode({}, "de", A2))
	#print("D2:", deepAnalyze2("ripe-atlas-anchor.franceix.net"))

	readHostName("netmetIPhost.txt", True)