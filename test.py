from envelope import envelope

a = envelope("fsd").smtp({"host": "/home/edvard/edvard/www/envelope/XX_smtp.ini", "port": 587}).subject("test3").from_("me@exmample.com").to("edvard.rejthar@nic.cz").signature().send(False)
print(str(a))
