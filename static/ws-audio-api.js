let audioContext = new AudioContext({
    latencyHint: "playback",
    sampleRate: 24000
});

(function (global) {
    var defaultConfig = {
        codec: {
            sampleRate: 24000,
            channels: 2,
            bufferSize: 512
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
            this.silence = new Float32Array(this.config.codec.bufferSize);
        }
    };

    WSAudioAPI.Player.prototype.AddChunk = function (chunk) {
        var _this = this;
        var floats = _this.decoder.decode(chunk)
        _this.audioQueue.write(floats[0])
        _this.audioQueueR.write(floats[1])
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

        this.scriptNode = audioContext.createScriptProcessor(this.config.codec.bufferSize, 2, 2);

        this.scriptNode.onaudioprocess = function (e) {
            if (_this.audioQueue.length() > _this.config.codec.bufferSize) {

                e.outputBuffer.copyToChannel(_this.audioQueue.read(_this.config.codec.bufferSize), 0)
                e.outputBuffer.copyToChannel(_this.audioQueueR.read(_this.config.codec.bufferSize), 1)

            } else {
                e.outputBuffer.getChannelData(0).set(_this.silence);
                e.outputBuffer.getChannelData(1).set(_this.silence);
            }
        };

        this.scriptNode.connect(audioContext.destination);
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