import * as yup from "yup" 

export const loginSchema = yup.object().shape({
    email: yup.string().email("Mail formatına uygun bir değer giriniz").required("Mail girilmesi zorunludur"),
    password: yup.string().required("Şifre girilmesi zorunludur")
})