import {TutanotaError} from "./TutanotaError"

export class NativeAuthenticationError extends TutanotaError {
	constructor(m) {
		super("NativeAuthenticationError", m)
	}

}