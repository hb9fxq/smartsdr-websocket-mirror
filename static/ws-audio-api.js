// https://github.com/Ivan-Feofanov/ws-audio-api
//    WebSockets Audio API
//
//    Opus Quality Settings
//    =====================
//    App: 2048=voip, 2049=audio, 2051=low-delay
//    Sample Rate: 8000, 12000, 16000, 24000, or 48000
//    Frame Duration: 2.5, 5, 10, 20, 40, 60
//    Buffer Size = sample rate/6000 * 1024

(function(global) {
	var defaultConfig = {
		codec: {
			sampleRate: 24000,
			channels: 2,
			app: 2049,
			frameDuration:10,
			bufferSize: 4096
		},
		server: 'wss://' + window.location.hostname + ':5000'
	};

	var audioContext = new(window.AudioContext || window.webkitAudioContext)();

	var WSAudioAPI = global.WSAudioAPI = {
		Player: function(config, socket) {
			this.config = config || {};
			this.config.codec = this.config.codec || defaultConfig.codec;
			this.config.server = this.config.server || defaultConfig.server;
			this.sampler = new Resampler(this.config.codec.sampleRate, audioContext.sampleRate, 2, this.config.codec.bufferSize);
			this.parentSocket = socket;
			this.decoder = new OpusDecoder(this.config.codec.sampleRate, this.config.codec.channels);
			this.silence = new Float32Array(this.config.codec.bufferSize);
		}
	};


	WSAudioAPI.Player.prototype.AddChunk = function (chunk){
		var _this = this;

		_this.audioQueue.write(_this.decoder.decode_float(chunk))



	}

	WSAudioAPI.Player.prototype.start = function() {
		var _this = this;

		this.audioQueue = {
			buffer: new Float32Array(0),

			write: function(newAudio) {
				var currentQLength = this.buffer.length;
				newAudio = _this.sampler.resampler(newAudio);
				var newBuffer = new Float32Array(currentQLength + newAudio.length);
				newBuffer.set(this.buffer, 0);
				newBuffer.set(newAudio, currentQLength);
				this.buffer = newBuffer;
			},

			read: function(nSamples) {
				var samplesToPlay = this.buffer.subarray(0, nSamples);
				this.buffer = this.buffer.subarray(nSamples, this.buffer.length);
				return samplesToPlay;
			},

			length: function() {
				return this.buffer.length;
			}
		};

		this.scriptNode = audioContext.createScriptProcessor(this.config.codec.bufferSize, 2, 2);

		this.scriptNode.onaudioprocess = function(e) {
			if (_this.audioQueue.length()) {
				e.outputBuffer.getChannelData(0).set(_this.audioQueue.read(_this.config.codec.bufferSize));
				e.outputBuffer.getChannelData(1).set(_this.audioQueue.read(_this.config.codec.bufferSize));
			} else {
				e.outputBuffer.getChannelData(0).set(_this.silence);
				e.outputBuffer.getChannelData(1).set(_this.silence);
			}
		};
		this.gainNode = audioContext.createGain();
		this.scriptNode.connect(this.gainNode);
		this.gainNode.connect(audioContext.destination);


      };

      WSAudioAPI.Player.prototype.getVolume = function() {
      	return this.gainNode ? this.gainNode.gain.value : 'Stream not started yet';
      };

      WSAudioAPI.Player.prototype.setVolume = function(value) {
      	if (this.gainNode) this.gainNode.gain.value = value;
      };

      WSAudioAPI.Player.prototype.stop = function() {
      	this.audioQueue = null;
      	this.scriptNode.disconnect();
      	this.scriptNode = null;
      	this.gainNode.disconnect();
      	this.gainNode = null;

      	if (!this.parentSocket) {
      		this.socket.close();
      	} else {
      		this.socket.onmessage = this.parentOnmessage;
      	}
      };
    })(window);
