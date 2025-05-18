import { createSlice } from '@reduxjs/toolkit'
import HomeIcon from '@mui/icons-material/Home';
import RadarIcon from '@mui/icons-material/Radar';

const initialState = {
  pages: 
    [
        {
            title:"Anasayfa",
            link: "/scan",
            icon: <HomeIcon/>
        },
        {
            title:"Eski taramalar",
            link:"/oldscan",
            icon: <RadarIcon/>
        }
    ],
  theme:true,
  colors: {
    headerLightColor: "rgba(161, 199, 222, 0.91)",
    bodyLightColor: "white",
    cardLightColor: "white",
    scanLightColor: "rgba(137, 185, 244, 0.613)",
    drawerLightColor: "white",
    lightText: "black",
    
    headerDarkColor: "rgba(12, 27, 36, 0.91)",
    bodyDarkColor: "rgba(39, 42, 43, 0.91)",
    cardDarkColor: "rgba(206, 206, 206, 0.91)",
    scanDarkColor: "rgba(70, 95, 126, 0.61)",
    drawerDarkColor: "rgba(26, 26, 26, 0.61)",
    darkText: "white",

  }

}

export const constantSlice = createSlice({
  name: 'constant',
  initialState,
  reducers: {
    changeTheme: (state) =>{
      state.theme = !state.theme
      localStorage.setItem("theme",state.theme)
    },
  },
})

export const { changeTheme,localThemeStorage } = constantSlice.actions

export default constantSlice.reducer