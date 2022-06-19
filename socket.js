const http = require("http");

const crypto = require("crypto");

const fs = require("fs");

const os = require("os");

// printing little endian or bid endian that you cpu is....

console.log(os.endianness());

// creating a http server

var server = http.createServer();

// http server upgrading event to websocket

server.addListener("upgrade",function(req,socket)
{
    // creating header for handshake

    // it takes req.headers["sec-websocket-key"] and append it with the socket magic key that is written in RFC 258EAFA5-E914-47DA-95CA-C5AB0DC85B11 and then encrypting it into sha1 with base64 encoding

    var respHeader = crypto.createHash('sha1').update(req.headers["sec-websocket-key"]+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest('base64');

    // creating http header for 101 switching protocol upgrading to tcp

    var response = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "+respHeader+"\r\n\r\n"; 

    // writing the response to browser

    socket.write(response);

    socket.setNoDelay(true);

    socket.setKeepAlive(true);

    // creating a socket message parser class

    var msgParse = new SocketParser(socket);    

    // listening to on data event, getting the messages to an array of buffer

    socket.addListener("data",function(buffer)
    {    
        console.log(buffer);
        msgParse.addBuffer(buffer);
    });

    // here where client or server ends the connections

    socket.addListener("end",function()
    {
        console.log("ok");
    });

    // here you have to handle all errors occurs related to tcp connections

    socket.addListener("error",function(err)
    {
        console.log(err);
    });
});

// here is where the magic happens

class SocketParser
{
    constructor(socket)
    {
        // initializing the variables and arrays

        this.buffer = [];
        this.prevfin;
        this.prevOpCode;
        this.prevLen;
        this.socket = socket;
        this.prevPacketDecoded = [];
        this.prevPacketText = "";
        this.curPacket = [];
        this.status = true;
    }  

    // this is a sample timer to start parsing the messages, its just a demo purpose its not the best way to start parsing messagses, it is written with setInterval so that you can see the logs how the data is comming into chunks and the parsing it

    startTimer()
    {
        var that = this;

        this.timer = setInterval(function()
        {
            that.GetPayload();
        },10);
    }

    // this method is used in the on data event where it was pushing buffers into an array

    addBuffer(buffer)
    {
        // if the buffer array is empty it will start the timer

        if(this.buffer.length === 0)
        {
            this.startTimer();
        }

        // it pushes all the buffers into an array that are coming from on data event

        this.buffer.push(buffer);

        // if current packet length is 0 then the current packet as only the current buffer

        // if the current packet length is not 0 then it append the latest buffer with the old one

        if(this.curPacket.length === 0)
        {
            this.curPacket = Buffer.concat([this.buffer.shift()]);
        }
        else
        {
            this.curPacket = Buffer.concat([this.curPacket, this.buffer.shift()]);
        }
    }

    // this method is invoked by the timer

    GetPayload()
    {
        // Here it is the checking if the this.curPacket is empty, then it will clear the interval 

        if(this.curPacket.length === 0)
        {
            clearInterval(this.timer);
            return;
        }

        // Here it is checking the the this.prevPacketText is empty string or not, this method is invoked when there is fin 1 without the occurance of previous message with fin 0

        if(this.prevPacketText === "")
        {
            // now we will get the first bit, to know bit and bytes read the following link.
            // https://www.javatpoint.com/java-data-types
            // 8 bits = 1 byte

            // first byte of the buffer

            var firstByte = this.curPacket[0];

            // getting the first bit the fetch the fin 0x80 is hex representation of decimal you can read hex conversion from google. & and >>> these are bit operators you can check this in javascript documentation. These are basics of javascript.

            this.prevfin = (firstByte & 0x80) >>> 7;

            // getting the opCode from the second bit of the first byte

            this.prevOpCode = firstByte & 0x0f;

            // here we are handling special opCode that we want to ignore for now.

            var payloadType;

            if ( this.prevOpCode >= 0x3 && this.prevOpCode <= 0x7  
            ||
            this.prevOpCode >= 0xB && this.prevOpCode <= 0xF)
            {
                console.log("Special frame recieved");
                return;
            }

            // now matching the opCode and setting payloadType string

            // if we recieve 0 that means packets are coming more and we need to continue to read the packets before parsing.

            // if we recieve 1 that means text and 2 means binary data

            // if we recieve 9 means client / server has disconnected and sends the opCode to other party

            // if we recieve ping then server will send pong to maintain heartbeat same goes for client.

            if(this.prevOpCode == 0x0)
            {
                payloadType = 'continuation';
            }
            else if(this.prevOpCode == 0x1)
            {
                payloadType = 'text';
            }
            else if(this.prevOpCode == 0x2)
            {
                payloadType = 'binary';
            }
            else if(this.prevOpCode == 0x8)
            {
                payloadType = 'connection close';
            }
            else if(this.prevOpCode == 0x9)
            {
                payloadType = 'ping';
            }
            else if(this.prevOpCode == 0xA)
            {
                payloadType = 'pong';
            }
            else
            {
                payloadType = 'reservedfornon-control';
            }

            // here we are printing the fin and opCode

            console.log("this.prevfin: "+this.prevfin);
            console.log(payloadType);

            // Here we are handling continuation flag and we are parsing the values and more packets are about to come.

            if(payloadType === "continuation")
            {
                this.parseMessage(this.prevfin);
                return;
            }

            // here if the fin = 1 and payloadType is text or binary means message is complete

            // if fin is 0 then we store the packet after parse and wait for next packet to parse and then we concatenate the packets to one.

            if(this.prevfin === 1 && (payloadType === "text" || payloadType === "binary"))
            {
                this.parseMessage(this.prevfin);
            }
            else if(this.prevfin === 0)
            {
                this.parseMessage(this.prevfin);
            }
        }
        else
        {
            // this case comes when previous fin = 0 and we store the packet to this.prevPacketText and then we parse the current packet and concatenate both.

            if(this.prevfin === 1)
            {
                this.parseMessage(1, "append");
            }
            else
            {
                this.parseMessage(this.prevfin);
            }
        }
    }

    // parsing method 

    parseMessage(finstatus, state)
    {
        // Here we get the second bytes

        var secondByte = this.curPacket[1];

        // first bit of the second bytes where we get the masking flag whether the message is masked or not, if not disconect the client. Masking means the data should be in XOR encryption

        var mask = (secondByte & 0x80) >>> 7;

        // if mask === 0 then get the next packet or disconect the client.

        if (mask === 0)
        {
            this.status = true;
            console.log('browse should always mask the payload data2');
            return;
        }

        // get the payload length of the buffer if it is 125 then boom thats it you dont have to get the packet length, and directly unmask the data,
        // if the payload Length is 126 then you need to read 2 bytes to get the actual payload length that is short value of 2 bytes.
        // if the payload length is 127 then message is very huge and is of 64 bit message that is 8 bytes to get the actual packet size.

        var payloadLength = (secondByte & 0x7f);
        var decoded = [];
        var text = "";
        var offset = 2;

        // if packet length is 126 then slice 2 bytes from the current packet and read convert the buffer to number to get the actual payload size

        // if the packet lenth is 127 then slice 8 bytes from the current packet and read convert the buffer to number to get the actual payload size

        if(payloadLength == 126)
        {
            payloadLength = this.curPacket.slice(offset, 4);

            payloadLength = payloadLength.readUInt16BE(0);

            offset += 2;
        }
        else if(payloadLength == 127)
        {
            payloadLength = this.curPacket.slice(offset, 16);

            payloadLength = payloadLength.readUInt64BE(0);

            offset += 8;
        }

        // here we are printing the payload lenth and the current packet length

        console.log("payloadLength:",payloadLength);
        console.log("currentBuffer:",this.curPacket.length);

        // here we are reading more 4 bytes to get the mask buffer

        var masks = this.curPacket.slice(offset, (offset + 4));

        var actualPayload = offset + 4;

        // getting the actual payload starting point

        var totalPayloadChunk = actualPayload + payloadLength;

        // if the current Packet size is less than payload lenth then we return it from here and wait for more packets to recieve

        if(payloadLength > this.curPacket.length)
        {
            return;
        }

        // now we iterate the actual payload to total payload chunk size and decode the payload with the mask buffer

        for (var i = actualPayload, j = 0; i < totalPayloadChunk; i++,j++)
        {
            decoded[j] = this.curPacket[i] ^ masks[j % 4];
            text += String.fromCharCode(this.curPacket[i] ^ masks[j % 4]);
        }

        // after the parsing the buffer now we slice the read packet from the actual buffer packet using slice

        this.curPacket = this.curPacket.slice(totalPayloadChunk);

        // if state is append that means we got fin 0 in previous packet and have stored the parsed packet into this.prevPacketText and second packet we have recieved the fin 1 and concatenate the previous with the current packet

        if(state === "append")
        {
            text = this.prevPacketText + text;
            this.prevPacketText = "";
            decoded = this.prevPacketDecoded.concat(decoded);
            this.prevPacketDecoded = [];
        }

        // if fin status == 0 then we are storing the parsed packet into his.prevPacketText and this.prevPacketDecoded for binary values 

        if(finstatus === 0)
        {
            this.prevLen = payloadLength;
            this.prevPacketText += text;
            this.prevPacketDecoded.concat(decoded);
            return;
        }

        // here we finally writing to a file to see whether we have recieved the exact packet from the client or not

        fs.appendFileSync("sample.txt", text.length+"\r\n");

        // Now we will implement the send method here. 

        // We will send message from server to client

        var message = "Hello from server";

        // getting the message length
        
        var messageSize = message.length;

        // creating two array one for creating headers and one for creating body

        var header = [];
        var sendData = [];

        // setting the opCode for sending the message to client this variable is integer 129 according to rfc

        var b1 =  0x80 | (0x1 & 0x0f);

        // setting to first byte of the header

        header[0] = b1;

        // if message length is less that or equal to 125 then we set the message size in the first byte of the header

        // if message lenth is greater than 125 and less than 65536 then we set the message length into the second and third byte of the header that is Short value

        // if message length is greater than equal to 65536 that is 64 bit message size then we write the byte size into the 8 bytes of the header

        if(messageSize <= 125)
        {
            header[1] = messageSize;
        }
        else if(messageSize > 125 && messageSize < 65536)
        {
            header[1] = 126;
            header[2] = (messageSize >> 8) & 255;
            header[3] = (messageSize) & 255;
        }
        else if(messageSize >= 65536)
        {
            header[1] = 127;
            header[2] = ( messageSize >> 56 ) & 255
            header[3] = ( messageSize >> 48 ) & 255
            header[4] = ( messageSize >> 40 ) & 255
            header[5] = ( messageSize >> 32 ) & 255
            header[6] = ( messageSize >> 24 ) & 255
            header[7] = ( messageSize >> 16 ) & 255
            header[8] = ( messageSize >>  8 ) & 255
            header[9] = ( messageSize       ) & 255
        }

        // now converting the message into ascii value this is not necessary.

        for(var i=0;i<messageSize;i++)
        {
            sendData[i] = message.charCodeAt(i); 
        }

        // concatenating the header with the body and converting it to buffer and sending it to the client thats it Kaboom, here we have build a successfully websocket for sending and recieving the values.

        // There is lot of things to improve, like handling the message in event based creating seperate method to send data handling multiple sockets even create custom protocol like websocket over tcp or udp.

        var arr = header.concat(sendData);

        var body = Buffer.from(arr);

       this.socket.write(body);
    }
}

server.listen(9100);