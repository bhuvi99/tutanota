package de.tutao.tutanota;

import org.json.JSONException;
import org.json.JSONObject;

public final class TutanotaCredentials {
    private String mailAddress;
    private String encryptedPassword;
    private String accessToken;
    private String userId;

    public TutanotaCredentials(String mailAddress, String encryptedPassword, String accessToken, String userId) {
        this.mailAddress = mailAddress;
        this.encryptedPassword = encryptedPassword;
        this.accessToken = accessToken;
        this.userId = userId;
    }

    public JSONObject toJSON() {
        try {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("mailAddress", mailAddress);
            jsonObject.put("encryptedPassword", encryptedPassword);
            jsonObject.put("accessToken", accessToken);
            jsonObject.put("userId", userId);
            return jsonObject;
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }

    public static TutanotaCredentials fromJSON(JSONObject jsonObject) {
        try {
            return new TutanotaCredentials(
                    jsonObject.getString("mailAddress"),
                    jsonObject.getString("encryptedPassword"),
                    jsonObject.getString("accessToken"),
                    jsonObject.getString("userId")
            );
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }
}
