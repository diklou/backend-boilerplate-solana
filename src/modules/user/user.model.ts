import mongoose from 'mongoose';
import toJSON from '../toJSON/toJSON';
import paginate from '../paginate/paginate';
import { roles } from '../../config/roles';
import { IUserDoc, IUserModel } from './user.interfaces';
import nacl from 'tweetnacl';
import base58 from 'bs58';

const userSchema = new mongoose.Schema<IUserDoc, IUserModel>(
	{
		address: {
			required: true,
			type: String,
			unique: true,
			immutable: true,
		},
		nonce: {
			type: String,
		},
		role: {
			type: String,
			enum: roles,
			default: 'user',
		},
	},
	{
		timestamps: true,
	}
);

// add plugin that converts mongoose to json
userSchema.plugin(toJSON);
userSchema.plugin(paginate);

/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
userSchema.static(
	'isEmailTaken',
	async function (email: string, excludeUserId: mongoose.ObjectId): Promise<boolean> {
		const user = await this.findOne({ email, _id: { $ne: excludeUserId } });
		return !!user;
	}
);

/**
 * Check if password matches the user's password
 * @param {string} password
 * @returns {Promise<boolean>}
 */
userSchema.method('isNonceMatch', async function (signature: string): Promise<boolean> {
	const user = this;
	const msg = `Welcome!\n\nPlease sign this message to verify ownership of the wallet.\n\nUnique Access Token: ${user.nonce}`;

	// 	const msgBufferHex = ethUtil.bufferToHex(Buffer.from(msg, 'utf8'));
	// 	const extracted_address = recoverPersonalSignature({
	// 		data: msgBufferHex,
	// 		sig: signature,
	// 	});

	return nacl.sign.detached.verify(
		new TextEncoder().encode(msg),
		base58.decode(signature),
		base58.decode(user.address)
	);
});

// userSchema.pre('save', async function (next) {
// 	const user = this;
// 	if (user.isModified('password')) {
// 		user.password = await bcrypt.hash(user.password, 8);
// 	}
// 	next();
// });

const User = mongoose.model<IUserDoc, IUserModel>('User', userSchema);

export default User;
