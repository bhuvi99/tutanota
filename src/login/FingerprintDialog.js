// @flow
import {Dialog} from "../gui/base/Dialog"

let dialog: ?Dialog

export function show() {
	dialog = Dialog.showActionDialog({
		title: () => "Auth",
		child: {view: () => "plz"},
		okAction: null
	})
}

export function close() {
	if (dialog) {
		dialog.close()
	}
}