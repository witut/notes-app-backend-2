const ClientError = require('../../exceptions/ClientError');

class AuthenticationsHandler {
  constructor(authenticationsService, userService, tokenManager, validator) {
    this._authenticationsService = authenticationsService;
    this._userService = userService;
    this._validator = validator;
    this._tokenManager = tokenManager;

    this.postAuthenticationHandler = this.postAuthenticationHandler.bind(this);
    this.putAuthenticationHandler = this.putAuthenticationHandler.bind(this);
    this.deleteAuthenticationHandler = this.deleteAuthenticationHandler.bind(this);
  }

  async postAuthenticationHandler(request, h) {
    try {
      this._validator.validatePostAuthenticationPayload(request.payload);
      const { username, password } = request.payload;
      const id = await this._userService.verifyUserCredential(username, password);
      const accessToken = this._tokenManager.generateAccessToken({ id });
      const refreshToken = this._tokenManager.generateRefreshToken({ id });
      // simpan token ke database
      await this._authenticationsService.addRefreshToken(refreshToken);
      // kembalikan response
      const response = h.response({
        status: 'success',
        message: 'Authentication berhasil ditambahkan',
        data: {
          accessToken,
          refreshToken,
        },
      });
      response.code(201);
      return response;
    } catch (error) {
      if (error instanceof ClientError) {
        const response = h.response({
          status: 'fail',
          message: error.message,
        });
        response.code(error.statusCode);
        return response;
      }

      // server error
      const response = h.response({
        status: 'error',
        message: 'Maaf, terjadi kegagalan pada server kami.',
      });
      response.code(500);
      console.error(error);
      return response;
    }
  }

  async putAuthenticationHandler(request, h) {
    try {
      this._validator.validatePutAuthenticationPayload(request.payload);
      const { refreshToken } = request.payload;
      // verifikasi token pada database dan signatire token
      await this._authenticationsService.verifyRefreshToken(refreshToken);
      const { id } = this._tokenManager.verifyRefreshToken(refreshToken);
      // buat accessToken yg baru
      const accessToken = this._tokenManager.generateAccessToken({ id });
      return {
        status: 'success',
        message: 'Access Token berhasil diperbarui',
        data: {
          accessToken,
        },
      };
    } catch (error) {
      if (error instanceof ClientError) {
        const response = h.response({
          status: 'fail',
          message: error.message,
        });
        response.code(error.statusCode);
        return response;
      }

      // server error
      const response = h.response({
        status: 'fail',
        message: 'Maaf, terjadi kegagalan pada server kami',
      });

      response.code(500);
      console.error(error);
      return response;
    }
  }

  // delete authentication handler
  async deleteAuthenticationHandler(request, h) {
    try {
      // validasi dulu, harus menyertakan refreshToken pada payloadnya
      this._validator.validateDeleteAuthenticationPayload(request.pauload);
      const { refreshToken } = request.payload;
      // memastikan refreshToken tersebut terdapat pada database
      await this._authenticationsService.verifyRefreshToken(refreshToken);
      // jika sudah terverifikasi, lanjut untuk prose penghapusan
      await this._authenticationsService.deleteRefreshToken(refreshToken);
      // kembalikan response sesuai skenario
      return {
        status: 'success',
        message: 'Refresh token berhasil dihapus',
      };
    } catch (error) {
      if (error instanceof ClientError) {
        const response = h.response({
          status: 'fail',
          message: error.message,
        });
        response.code(error.statusCode);
        return response;
      }

      // server error
      const response = h.response({
        status: 'error',
        message: 'Maaf terjadi kegagalan pada server kami',
      });
      response.code(500);
      return response;
    }
  }
}
module.exports = AuthenticationsHandler;
