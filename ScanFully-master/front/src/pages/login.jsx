import React from 'react'
import {useFormik} from "formik"
import "../css/login.css"
import { loginSchema } from '../schema/loginSchema';
import { useNavigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { Button } from '@mui/material';


function Login() {

  const navigate = useNavigate()
  const {theme,colors} = useSelector((store)=>store.constant)

  const dispatch = useDispatch()

  const {errors,handleChange,handleSubmit,values} = useFormik({
    initialValues: {
      email:"",
      password:""
    },
    validationSchema: loginSchema,

    onSubmit: (values,actions)=>{
      // API istekleri
      // Değerler doğruysa scan kısmına yönlendir
      navigate("/scan")
    }
  });

  return (
    <div style={{display:'flex',flexDirection:"row",justifyContent:"space-around",height:"100vh",backgroundColor: theme ? colors.bodyDarkColor : colors.bodyLightColor}}>

      <div className='scanFully scanFullyText'>
          ScanFully
      </div>
      
      <div className='inputDiv'>
        <form onSubmit={handleSubmit}>
          <div>
            {/* <label>Email</label><br/> */}
            <input className='inputStyle' id='email' value={values.email} onChange={handleChange} type='text' placeholder='Email giriniz'></input>
            {errors && <p className='errorMessage'>{errors.email}</p>}
          </div>
          <div>
            {/* <label>Şifre</label><br/> */}
            <input className='inputStyle' id="password" value={values.password} onChange={handleChange} type='password' placeholder='Şifre giriniz'></input>
            {errors && <p className='errorMessage'>{errors.password}</p>}
          </div>
          <button className='loginButton' type='submit'>Giriş yap</button>
        </form>
      </div>
    </div>
  )
}

export default Login