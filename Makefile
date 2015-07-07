CC = gcc
CFLAGS = -g -Wall -O2
CFLAGS += -I/usr/include/libusb-1.0
LIBS = -lusb-1.0
TARGET = usb_flasher

SRCFOLDER = src
INCFOLDER = include
OBJFOLDER = src
BINFOLDER = bin

SOURCES = $(wildcard $(SRCFOLDER)/*.c)
OBJECTS = $(patsubst %.c,$(OBJFOLDER)/%.o,$(notdir $(wildcard $(SRCFOLDER)/*.c)))

all: $(OBJECTS)
	$(CC) $^ $(LIBS) -o $(BINFOLDER)/$(TARGET)

$(OBJFOLDER)/%.o: $(SRCFOLDER)/%.c
	$(CC) $(CFLAGS) -c -o $@ $< -I$(INCFOLDER)

clean:
	@rm -rf $(OBJFOLDER)/*.o $(BINFOLDER)/$(TARGET)
