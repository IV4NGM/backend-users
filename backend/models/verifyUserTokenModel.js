const mongoose = require('mongoose')

const verifyUserTokenSchema = mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User'
  },
  token: {
    type: String,
    required: true
  },
  expiresAt: {
    type: Date,
    default: () => {
      return new Date(Date.now() + 24 * 60 * 60 * 1000)
    }
  }
}, {
  timestamps: true
})

module.exports = mongoose.model('VerifyUserToken', verifyUserTokenSchema)
