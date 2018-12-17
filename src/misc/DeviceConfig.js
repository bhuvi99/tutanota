// @flow
import {assertMainOrNodeBoot, isApp} from "../api/Env"
import {themeId} from "../gui/theme"
import {client} from "./ClientDetector"
import {getFromSecureStorage, putIntoSecureStorage} from "../native/SystemApp"
import {nativeApp} from "../native/NativeWrapper"

assertMainOrNodeBoot()

const ConfigVersion = 2
const LocalStorageKey = 'tutanotaConfig'
const secureStorageKey = 'tutanotaCredentials'

/**
 * Device config for internal user auto login. Only one config per device is stored.
 */
class DeviceConfig {
	_version: number;
	_credentials: Credentials[];
	_theme: ThemeId;
	_nativeAuthRequired: ?boolean;

	/**
	 * @param config The config to copy from
	 */
	constructor() {
		this._version = ConfigVersion
		this._load()
	}

	_load(): void {
		this._credentials = []
		let loadedConfigString = client.localStorage() ? localStorage.getItem(LocalStorageKey) : null
		let loadedConfig = loadedConfigString != null ? JSON.parse(loadedConfigString) : null
		this._theme = (loadedConfig && loadedConfig._theme) ? loadedConfig._theme : 'light'
		if (loadedConfig && loadedConfig._version === ConfigVersion) {
			if (loadedConfig.credentials != null) {
				this._credentials = loadedConfig._credentials
			}
			if (loadedConfig._nativeAuthenticationRequired != null) {
				this._nativeAuthRequired = loadedConfig._nativeAuthRequired
			}
		}
	}

	_loadCredentialsFromNative(): Promise<Credentials[]> {
		return nativeApp
			.initialized()
			.then(() => getFromSecureStorage(secureStorageKey))
			.then(json => {
				if (json != null) {
					this._credentials = JSON.parse(json)
					return this._credentials
				}
				return []
			})
	}

	getStoredAddresses(): string[] {
		return this._credentials.map(c => c.mailAddress)
	}

	get(mailAddress: string): ?Credentials {
		return this._credentials.find(c => c.mailAddress === mailAddress)
	}

	getByUserId(id: Id): ?Credentials {
		return this._credentials.find(c => c.userId === id)
	}

	set(credentials: Credentials) {
		let index = this._credentials.findIndex(c => c.mailAddress === credentials.mailAddress)
		if (index !== -1) {
			this._credentials[index] = credentials
		} else {
			this._credentials.push(credentials)
		}
	}

	delete(mailAddress: string) {
		this._credentials.splice(this._credentials.findIndex(c => c.mailAddress === mailAddress), 1)
	}

	deleteByAccessToken(accessToken: string) {
		this._credentials.splice(this._credentials.findIndex(c => c.accessToken === accessToken), 1)
	}

	store(): Promise<void> {
		if (isApp()) {
			return this._saveCredentialsToSecureStorage(false).then(() => {
				localStorage.setItem(LocalStorageKey, JSON.stringify({_version: this._version, _theme: this._theme}))
			})
		} else {
			try {
				localStorage.setItem(LocalStorageKey, JSON.stringify(this))
			} catch (e) {
				// may occur in Safari < 11 in incognito mode because it throws a QuotaExceededError
				console.log("could not store config", e)
			}
			return Promise.resolve()
		}
	}

	_saveCredentialsToSecureStorage(regenerate: boolean): Promise<void> {
		return putIntoSecureStorage(secureStorageKey, JSON.stringify(this._credentials), Boolean(this._nativeAuthRequired), regenerate)
	}

	getAll(): Credentials[] {
		// make a copy to avoid changes from outside influencing the local array
		return JSON.parse(JSON.stringify(this._credentials));
	}

	getAllInternal(): Credentials[] {
		// make a copy to avoid changes from outside influencing the local array
		return this.getAll().filter(credential => credential.mailAddress.indexOf("@") > 0)
	}

	getTheme(): ThemeId {
		return this._theme
	}

	setTheme(theme: ThemeId) {
		if (this._theme !== theme) {
			this._theme = theme
			themeId(theme)
			// TODO: save only localStorage things here
			this.store()
		}
	}

	setNativeAuthRequired(required: boolean) {
		this._nativeAuthRequired = required
		this._saveCredentialsToSecureStorage(true)
	}
}


export const deviceConfig = new DeviceConfig()