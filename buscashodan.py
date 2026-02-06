import pandas as pd
import requests

from shodan import Shodan
from datetime import datetime
from tqdm import tqdm
from ipwhois import IPWhois

# Consulta a Shodan. Necesita API key y cuenta de pago
# De todo lo que devuelve nos quedamos con la organizacion y los puertos abiertos
# TODO - Ver si tambien nos interesa guardar los tags
def analizar_shodan(ip):

    api = Shodan('TU_API_KEY')
    resultados_shodan = dict()

    try:
        respuesta_shodan = api.host(ip)
        resultados_shodan = {
            "organizacion_shodan" : respuesta_shodan['org'],
            "puertos_shodan" : respuesta_shodan['ports'],
            "detalles_shodan" : "https://www.shodan.io/host/" + ip
        }

    except:
        respuesta_shodan = {
            "organizacion_shodan" : "error",
            "puertos_shodan" : "error",
            "detalles_shodan" : "error"
        }

    return resultados_shodan

# Consulta a whois. Nos quedamos con el ASN y el pais al que pertenece
def consulta_whois(ip):

    respuesta_whois = dict()

    try:
        query_whois = IPWhois(ip)
        respuesta_whois = query_whois.lookup_rdap()
        resultados_whois = {
            "ASN" : respuesta_whois["asn"],
            "descripcion_asn" : respuesta_whois["asn_description"],
            "pais" : respuesta_whois["asn_country_code"]
        }

    except:
        resultados_whois = {
            "ASN" : "error",
            "descripcion_asn" : "error",
            "pais" : "error"
        }

    return resultados_whois

# Consulta a la API de ipquery. Gratis y no necesita API key
# Nos quedamos con booleanos sobre si la IP es de VPN, Tor, proxy o datacenter
def consulta_ipquery(ip):

    url_ipquery = f'https://api.ipquery.io/{ip}'
    diccionario_riesgo_ip = dict()

    try:
        info_riesgo_ip = requests.get(url_ipquery)
        diccionario_riesgo_ip = {
            "vpn" : info_riesgo_ip.json()["risk"]["is_vpn"],
            "tor" : info_riesgo_ip.json()["risk"]["is_tor"],
            "proxy" : info_riesgo_ip.json()["risk"]["is_proxy"],
            "datacenter" : info_riesgo_ip.json()["risk"]["is_datacenter"]
            }

    except:
        diccionario_riesgo_ip = {
            "vpn" : "error",
            "tor" : "error",
            "proxy" : "error",
            "datacenter" : "error"
            }

    return diccionario_riesgo_ip

def main():

    lista_resultados = []

    with open(r"ips.txt", 'r') as contar_líneas:
        total_líneas = len(contar_líneas.readlines())
        contar_líneas.close()

    fichero_ips = open('ips.txt', 'r')
    # Para cada IP obtenemos la info y vamos poblando los resultados en un diccionario
    for i in tqdm(range(0,total_líneas), total=total_líneas, desc="Analizando IPs"):
        diccionario_resultados = dict()
        ip = fichero_ips.readline()[:-1]
        diccionario_resultados.update(ip)
        diccionario_resultados.update(analizar_shodan(ip))
        diccionario_resultados.update(consulta_whois(ip))
        diccionario_resultados.update(consulta_ipquery(ip))
        # Una vez completo el diccionario lo metemos en una lista
        lista_resultados.append(diccionario_resultados)

    fichero_ips.close()
    # Convertimos la lista de diccionarios en un dataframe de pandas
    df = pd.DataFrame(lista_resultados)
    fecha = datetime.now().strftime('%Y%m%d%H%m%s')
    nombre_fichero_salida_excel = 'analisis_ip_' + fecha + '.xlsx'
    # Exportamos a excel
    df.to_excel(nombre_fichero_salida_excel)

if __name__ == "__main__":
    main()
