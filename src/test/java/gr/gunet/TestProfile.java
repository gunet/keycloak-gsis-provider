package gr.gunet;

public enum TestProfile {
    VALID("User123", "user123", "ΠΑΥΛΟΣ", "ΠΑΠΑΔΟΠΟΥΛΟΣ", "ΚΩΝΣΤΑΝΤΙΝΟΣ", "ΜΑΡΙΑ", "1994", "094014201"),
    VALID_TIN_DOUBLE_ZERO("User456", "user456", "ΜΑΡΙΑ", "ΓΕΩΡΓΙΟΥ", "ΝΙΚΟΛΑΟΣ", "ΕΛΕΝΗ", "1985", "00094014201"),
    INVALID_TIN("User789", "user789", "ΙΩΑΝΝΗΣ", "ΔΗΜΗΤΡΙΟΥ", "ΠΑΝΑΓΙΩΤΗΣ", "ΣΟΦΙΑ", "1990", "123456789"),
    MALFORMED("User999", "user999", "INVALID", "INVALID", "", "", "", "094014201"),
    WITHOUT_USERINFO(null, null, null, null, null, null, null, null),
    SPECIAL_CHARS("User999", "user999", "ΜΑΡΙΑ-ΕΛΕΝΗ", "ΠΑΠΑΔΟΠΟΥΛΟΣ-ΓΕΩΡΓΙΟΥ", "ΚΩΝΣΤΑΝΤΙΝΟΣ", "ΑΙΚΑΤΕΡΙΝΗ",
            "1988", "094014201"),
    NULL_TAXID("User888", "user888", "ΤΕΣΤ", "ΤΕΣΤ", "", "", "", null),
    EMPTY("", "", "", "", "", "", "", ""),
    INVALID_TIN_LESS("User123", "user123", "ΠΑΥΛΟΣ", "ΠΑΠΑΔΟΠΟΥΛΟΣ", "ΚΩΝΣΤΑΝΤΙΝΟΣ", "ΜΑΡΙΑ", "1994", "01111111"),
    INVALID_TIN_MORE("User123", "user123", "ΠΑΥΛΟΣ", "ΠΑΠΑΔΟΠΟΥΛΟΣ", "ΚΩΝΣΤΑΝΤΙΝΟΣ", "ΜΑΡΙΑ", "1994", "0111111111"),
    INVALID_TIN_MALFORMED("User123", "user123", "ΠΑΥΛΟΣ", "ΠΑΠΑΔΟΠΟΥΛΟΣ", "ΚΩΝΣΤΑΝΤΙΝΟΣ", "ΜΑΡΙΑ", "1994",
            "09A01420B1");

    private final String userid;
    private final String username;
    private final String firstname;
    private final String lastname;
    private final String fathername;
    private final String mothername;
    private final String birthyear;
    private final String taxid;

    TestProfile(String userid, String username, String firstname, String lastname, String fathername,
            String mothername, String birthyear, String taxid) {
        this.userid = userid;
        this.username = username;
        this.firstname = firstname;
        this.lastname = lastname;
        this.fathername = fathername;
        this.mothername = mothername;
        this.birthyear = birthyear;
        this.taxid = taxid;
    }

    public String xml() {
        if (this == EMPTY)
            return "";
        if (this == WITHOUT_USERINFO)
            return "<root>\n  <otherdata value=\"test\"/>\n</root>";
        if (this == MALFORMED)
            return "<root>\n  <userinfo userid=\"User999\" taxid=\"094014201\" lastname=\"INVALID\"\n</root>";

        StringBuilder sb = new StringBuilder();
        sb.append("<root>\n  <userinfo");
        if (userid != null)
            sb.append(" userid=\"").append(userid).append("\"");
        if (taxid != null)
            sb.append(" taxid=\"").append(taxid).append("\"");
        if (lastname != null)
            sb.append(" lastname=\"").append(lastname).append("\"");
        if (firstname != null)
            sb.append(" firstname=\"").append(firstname).append("\"");
        if (fathername != null)
            sb.append(" fathername=\"").append(fathername).append("\"");
        if (mothername != null)
            sb.append(" mothername=\"").append(mothername).append("\"");
        if (birthyear != null)
            sb.append(" birthyear=\"").append(birthyear).append("\"");
        sb.append("/>\n</root>");
        return sb.toString();
    }

    public String getUserid() {
        return userid;
    }

    public String getUsername() {
        return username;
    }

    public String getFirstname() {
        return firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public String getFathername() {
        return fathername;
    }

    public String getMothername() {
        return mothername;
    }

    public String getBirthyear() {
        return birthyear;
    }

    public String getTaxid() {
        return taxid;
    }

    public String getNormalizedTaxid() {
        return taxid == null ? null : gr.gunet.utils.Validator.normalizeTin(taxid);
    }
}
