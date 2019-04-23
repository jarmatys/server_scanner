import nmap
import socket
from contextlib import closing
import requests
import dns.resolver

#sprawdzanie netcatem połączenia z adresem IP
def checking_connection(host):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host,80)) == 0:
            return "open"
        else:
            return "close"

#adres serwera który skanujemy
serv_adress = "156.17.88.0/24"

nm = nmap.PortScanner()

#wyszukaj wszystkie adresy po porcie 80
nm.scan(hosts=serv_adress, arguments='-p 80')

#print(nm.scaninfo())
#print(nm.all_hosts())
print("Ilość adresów nasłuchujących na porcie 80: "+ str(len(nm.all_hosts())))

#pętla po wszystkich adresach na danym serwerze
for host in nm.all_hosts():

    temp_str = ""

    #sprawdanie czy połaczenie jest otwarte
    if checking_connection(host) == "open":

        #wyświetlenie adresu serwera
        temp_str += host + " | "

        #wyświetlenie nazwy serwera
        if(nm[host].hostname()!=""):
            temp_str += nm[host].hostname() + " | "

        #wyświetlenie typu serwera
        try:
            response = requests.head("http://"+host+":80", allow_redirects=True)
            temp_str += response.headers['server'] + " | "
        except:
            temp_str += "Brak headera" + " | "

        #wyświetlanie maila osoby odpowiedzialnej za domenę
        try:
            if (nm[host].hostname() != ""):
                answers = dns.resolver.query(nm[host].hostname(), 'SOA')

            for rdata in answers:
                temp_str += str(rdata.rname).replace('.','@',1) + " "
        except:
            temp_str += "Brak maila" + "\n"

        print(temp_str)
        temp_str = ""

        #up or down
        #print(nm[host].state())
