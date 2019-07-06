MMARK=mmark
XML2RFC=xml2rfc
SOURCES= etm.md 
XML=$(SOURCES:.md=.xml)
TXT=$(SOURCES:.md=.txt)

all: $(XML) $(TXT)

%.xml : %.md
	$(MMARK) -xml2 -page $< > $@ 
	
%.txt : %.xml
	$(XML2RFC) $< --text $@

upload:
	scp etm.md  down.dsg.cs.tcd.ie:/var/www/misc/
	scp etm.xml  down.dsg.cs.tcd.ie:/var/www/misc/
	scp etm.txt  down.dsg.cs.tcd.ie:/var/www/misc/

clean:
	rm $(XML)
	rm $(TXT)
