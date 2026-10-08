"""
Leviathan OSINT v4.0 — Gold Dataset
200 ejemplos perfectos × oversample 5x en cada entrenamiento.
El modelo nunca se desvía del "norte verdadero" aunque hayas
investigado solo bots por semanas.
"""
GOLD_DATASET: dict[str, list[str]] = {

    "entity_type": [
        # emails
        "__label__email usuario@gmail.com", "__label__email test@empresa.mx",
        "__label__email admin@servidor.com", "__label__email contacto@dominio.com.mx",
        "__label__email no-reply@banco.mx", "__label__email soporte@tienda.net",
        "__label__email jgarcia@corporativo.mx", "__label__email info@startup.io",
        "__label__email ventas@negocio.com", "__label__email prueba@hotmail.com",
        "__label__email user123@outlook.com", "__label__email nombre.apellido@trabajo.com",
        # phones
        "__label__phone 6641234567", "__label__phone +526641234567",
        "__label__phone 5512345678", "__label__phone 3312345678",
        "__label__phone 8112345678", "__label__phone 6671234567",
        "__label__phone 9981234567", "__label__phone 4421234567",
        "__label__phone 6681234567", "__label__phone 7441234567",
        "__label__phone 2221234567", "__label__phone 9991234567",
        # domains
        "__label__domain google.com", "__label__domain empresa.mx",
        "__label__domain banco.com.mx", "__label__domain gobierno.gob.mx",
        "__label__domain tienda.com", "__label__domain api.servicio.io",
        "__label__domain mail.servidor.com", "__label__domain cdn.empresa.net",
        "__label__domain blog.persona.com", "__label__domain app.startup.mx",
        # ips
        "__label__ip 192.168.1.1", "__label__ip 8.8.8.8",
        "__label__ip 1.1.1.1", "__label__ip 187.189.45.23",
        "__label__ip 201.168.1.100", "__label__ip 10.0.0.1",
        "__label__ip 172.16.0.1", "__label__ip 45.33.32.156",
        "__label__ip 104.21.0.1", "__label__ip 198.41.0.4",
        # usernames
        "__label__username jgarcia667", "__label__username usuario_mx",
        "__label__username dev_python", "__label__username hacker_eth",
        "__label__username luissanchez", "__label__username darkweb_user",
        "__label__username el_wero", "__label__username mx_security",
        "__label__username coding_king", "__label__username network_admin",
        # persons
        "__label__person juan garcia lopez", "__label__person maria hernandez",
        "__label__person carlos roberto mendoza", "__label__person ana laura perez",
        "__label__person jose antonio ramirez", "__label__person claudia vazquez",
        "__label__person miguel angel torres", "__label__person sofia martinez",
        # crypto
        "__label__crypto 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "__label__crypto 0x742d35Cc6634C0532925a3b8D4C9B4438f44e92",
        "__label__crypto bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "__label__crypto 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        # breach
        "__label__breach rockyou2021", "__label__breach linkedin2012",
        "__label__breach adobe2013", "__label__breach equifax2017",
        "__label__breach rappi2023", "__label__breach yahoo2016",
        # asn
        "__label__asn AS13335", "__label__asn AS15169", "__label__asn AS8075",
        "__label__asn AS16509", "__label__asn AS14618",
        # plate
        "__label__plate ABC123D", "__label__plate SIN1234A",
        "__label__plate CDMX567B", "__label__plate JC89XY",
    ],

    "handle_class": [
        # bots
        "__label__bot user123456", "__label__bot bot_spam_2024",
        "__label__bot auto_follow99", "__label__bot repost_machine",
        "__label__bot crypto_bot_eth", "__label__bot news_bot_mx",
        "__label__bot follower_bot1", "__label__bot spam_account7831",
        "__label__bot like_farm_account", "__label__bot automated_poster",
        "__label__bot xyz12345678", "__label__bot aaaa1234",
        "__label__bot generated_user_9182", "__label__bot temp_account_mx",
        # real_person
        "__label__real_person jgarcia.dev", "__label__real_person luis.sanchez",
        "__label__real_person maria_perez", "__label__real_person carlos.mx",
        "__label__real_person ana.laura.h", "__label__real_person dev_wero",
        "__label__real_person security_researcher", "__label__real_person osint_analyst",
        "__label__real_person pentester_mx", "__label__real_person lsanchez_infosec",
        "__label__real_person j.garcia.667", "__label__real_person m.hernandez2",
        # corporate
        "__label__corporate empresa_oficial", "__label__corporate bancomex",
        "__label__corporate telcel_support", "__label__corporate pemex_oficial",
        "__label__corporate bbva_mx", "__label__corporate cinepolis_mex",
        "__label__corporate liverpool_tienda", "__label__corporate oxxo_mx",
        "__label__corporate soriana_oficial", "__label__corporate liverpool_oficial",
        # anonymous
        "__label__anonymous x_user_anon", "__label__anonymous nobody_here",
        "__label__anonymous ghost_user", "__label__anonymous darkweb_anon",
        "__label__anonymous unknown_mx", "__label__anonymous anon_researcher",
        "__label__anonymous private_user", "__label__anonymous noname_hax",
    ],

    "content_relevance": [
        # relevant
        "__label__relevant email encontrado en breach de datos linkedin 2012",
        "__label__relevant telefono +52664 detectado en fuga rappi 2023",
        "__label__relevant username activo en github con repositorios de seguridad",
        "__label__relevant dominio registrado hace 2 semanas sospechoso",
        "__label__relevant wallet bitcoin con 50 transacciones confirmadas",
        "__label__relevant ip con puertos abiertos 22 80 443 detectada en shodan",
        "__label__relevant correo electronico confirmado por hibp en 3 breaches",
        "__label__relevant perfil telegram publico con 5000 suscriptores",
        "__label__relevant nombre completo con curp asociado a vehiculo",
        "__label__relevant placa vehicular registrada en repuve sin reporte robo",
        "__label__relevant mencion en foro darkweb indice publico ahimia",
        "__label__relevant asn de empresa colombiana con ips en lista negra",
        # noise
        "__label__noise lorem ipsum dolor sit amet consectetur adipiscing elit",
        "__label__noise esta pagina esta en construccion vuelva pronto gracias",
        "__label__noise 404 not found the requested url was not found on this server",
        "__label__noise pagina principal inicio contacto acerca quienes somos",
        "__label__noise cookie policy privacy policy terms of service footer",
        "__label__noise captcha verification please confirm you are not a robot",
        "__label__noise cloudflare ddos protection waiting room please wait",
        "__label__noise access denied you do not have permission to view this page",
        "__label__noise error 403 forbidden server understood the request refused",
        "__label__noise google analytics javascript tracking pixel utm source",
        "__label__noise menu navegacion inicio productos servicios blog contacto",
        "__label__noise robots txt sitemap xml disallow allow user agent crawlers",
    ],

    "threat_relevance": [
        # threat
        "__label__threat credenciales expuestas en breach masivo contrasenas hash",
        "__label__threat ip clasificada como maliciosa en virustotal greynoise scanner",
        "__label__threat mencion en lista ransomware victima lockbit blackcat",
        "__label__threat interpol red notice persona buscada internacionalmente",
        "__label__threat ofac sdn list empresa sancionada por tesoro usa",
        "__label__threat dominio asociado a phishing campana activa detectada",
        "__label__threat wallet crypto asociada a exchange de fondos ilicitos chainalysis",
        "__label__threat multiple breach hits email contrasena expuesta texto plano",
        "__label__threat simswap risk detectado numero telefono vulnerado operador",
        "__label__threat servidor con vulnerabilidades criticas cve sin parche activo",
        # informational
        "__label__informational perfil publico github desarrollador repositorios open source",
        "__label__informational dominio corporativo con certificado ssl valido emitido",
        "__label__informational telefono movil postpago carrier verificado activo",
        "__label__informational ip residencial isp proveedor internet consumer",
        "__label__informational wallet bitcoin con actividad normal compras online",
        "__label__informational subdominio cdn entrega contenido estatico sitio web",
        "__label__informational perfil linkedin publico historial laboral empresa conocida",
        "__label__informational asn de google amazon cloudflare infraestructura normal",
        "__label__informational email con dominio corporativo formato nombre apellido",
        "__label__informational cuenta reddit 5 anos karma positivo usuario activo",
        # noise
        "__label__noise datos insuficientes para clasificar entidad sin contexto",
        "__label__noise resultado de busqueda irrelevante sin relacion con target",
        "__label__noise contenido duplicado misma informacion multiples fuentes upstream",
    ],

    "region_hint": [
        # mx
        "__label__mx +52 664 123 4567 tijuana baja california mexico",
        "__label__mx 667 culiacan sinaloa lada mexico telcel",
        "__label__mx .com.mx dominio mexico empresa mexicana",
        "__label__mx cdmx ciudad de mexico colonia centro delegacion cuauhtemoc",
        "__label__mx rfc registro federal contribuyentes sat mexico",
        "__label__mx curp clave unica registro poblacion mexico",
        "__label__mx repuve placa vehicular registro mx",
        "__label__mx rappi mercadolibre amazon.com.mx compras en linea mexico",
        "__label__mx oxxo seven eleven tienda de conveniencia mx",
        "__label__mx bancomer bbva banamex banorte banco mexicano",
        # us
        "__label__us +1 212 new york united states us",
        "__label__us 310 los angeles california us area code",
        "__label__us .gov .edu us government education domain",
        "__label__us 192 168 american provider isp comcast att",
        "__label__us social security number ssn united states",
        # es
        "__label__es +34 91 madrid spain espana",
        "__label__es .es dominio espana empresa espanola",
        "__label__es dni nif numero identificacion espana",
        # latam
        "__label__latam colombia bogota +57 latinoamerica",
        "__label__latam argentina buenos aires +54 latam",
        "__label__latam brazil brasil +55 sao paulo rio",
        "__label__latam chile santiago +56 latam sudamerica",
        # other
        "__label__other unknown region no latin america",
        "__label__other vpn proxy tor exit node ip anonimo",
        "__label__other onion dark web hidden service tor network",
    ],
}
