
all: introduction.html introduction.pdf

%.pdf: %.adoc
	asciidoctor-pdf $^

%.html: %.adoc
	asciidoctor $^
