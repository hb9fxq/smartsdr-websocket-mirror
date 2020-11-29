let audioContext = new AudioContext({
    latencyHint: "playback",
    sampleRate: 24000
});

let myArrayBuffer = audioContext.createBuffer(2, 48e3, 24e3);

(function (global) {
    var defaultConfig = {
        codec: {
            sampleRate: 24e3,
            channels: 2,
            bufferSize: 1024*8
        },
        server: 'wss://' + window.location.hostname + ':5000'
    };

    var WSAudioAPI = global.WSAudioAPI = {
        Player: function (config, socket) {
            this.config = config || {};
            this.config.codec = this.config.codec || defaultConfig.codec;
            this.config.server = this.config.server || defaultConfig.server;
            this.parentSocket = socket;
            this.decoder = new libopus.Decoder(this.config.codec.channels, this.config.codec.sampleRate);
        }
    };


    WSAudioAPI.Player.prototype.AddChunk = function (chunk) {
        var _this = this;
        var floats = _this.decoder.decode(chunk)

        _this.audioQueue.write(floats[0])
        _this.audioQueueR.write(floats[1])


        var frameCount = audioContext.sampleRate * 2.0;

        if(_this.audioQueue.length() > frameCount) {


            myArrayBuffer.copyToChannel(_this.audioQueue.read(frameCount), 0, 0)
            myArrayBuffer.copyToChannel(_this.audioQueueR.read(frameCount), 1, 0)

            var source = audioContext.createBufferSource();
            source.buffer = myArrayBuffer;
            source.connect(audioContext.destination);
            source.start();
        }
    }

    WSAudioAPI.Player.prototype.start = function () {
        var _this = this;

        this.audioQueue = {
            buffer: new Float32Array(0),

            write: function (newAudio) {
                var currentQLength = this.buffer.length;
                var newBuffer = new Float32Array(currentQLength + newAudio.length);
                newBuffer.set(this.buffer, 0);
                newBuffer.set(newAudio, currentQLength);
                this.buffer = newBuffer;
            },

            read: function (nSamples) {
                var samplesToPlay = this.buffer.subarray(0, nSamples);
                this.buffer = this.buffer.subarray(nSamples, this.buffer.length);
                return samplesToPlay;
            },

            length: function () {
                return this.buffer.length;
            }
        };

        this.audioQueueR = {
            buffer: new Float32Array(0),

            write: function (newAudio) {
                var currentQLength = this.buffer.length;
                var newBuffer = new Float32Array(currentQLength + newAudio.length);
                newBuffer.set(this.buffer, 0);
                newBuffer.set(newAudio, currentQLength);
                this.buffer = newBuffer;
            },

            read: function (nSamples) {
                var samplesToPlay = this.buffer.subarray(0, nSamples);
                this.buffer = this.buffer.subarray(nSamples, this.buffer.length);
                return samplesToPlay;
            },

            length: function () {
                return this.buffer.length;
            }
        };
    };


    WSAudioAPI.Player.prototype.getVolume = function () {
        return this.gainNode ? this.gainNode.gain.value : 'Stream not started yet';
    };

    WSAudioAPI.Player.prototype.setVolume = function (value) {
        if (this.gainNode) this.gainNode.gain.value = value;
    };

    WSAudioAPI.Player.prototype.stop = function () {
        this.audioQueue = null;
        this.gainNode.disconnect();
        this.gainNode = null;

        if (!this.parentSocket) {
            this.socket.close();
        } else {
            this.socket.onmessage = this.parentOnmessage;
        }
    };
})(window);