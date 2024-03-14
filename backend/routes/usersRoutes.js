const { Router } = require('express')
const router = Router()
const { createUser, sendVerificationEmail, verifyUser, sendResetEmail, resetPassword, loginUser, getUser, getAllUsers, updateUser, deleteUser } = require('@/controllers/usersControllers')
const { protect, adminProtect } = require('@/middleware/authMiddleware')

router.post('/', createUser)
router.post('/login', loginUser)
router.post('/send-verification-email', sendVerificationEmail)
router.post('/verify', verifyUser)
router.post('/send-reset-email', sendResetEmail)
router.post('/reset-password', resetPassword)
router.get('/', protect, getUser)
router.get('/all', protect, adminProtect, getAllUsers)
router.put('/', protect, updateUser)
router.delete('/', protect, deleteUser)

module.exports = router
