import React, { useEffect, useState } from 'react'
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import MenuIcon from '@mui/icons-material/Menu';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import WbSunnyIcon from '@mui/icons-material/WbSunny';
import {AppBar,Typography,Toolbar,IconButton} from '@mui/material/';
import { Drawer,Box,List,ListItem,ListItemButton,ListItemIcon,ListItemText,Button } from '@mui/material';
import { changeTheme, localThemeStorage } from '../redux/constantSlice';

function Appbar() {


  const dispatch = useDispatch()
  const {pages,theme,colors} = useSelector((store)=>store.constant)
  const navigate = useNavigate()

  const iconChangeTheme = () => {
    dispatch(changeTheme())
  }
  
  const [isOpen,setOpen] = useState(false)
  
  const Forward = (link)=>{
    setOpen(false)
    navigate(link)
  }
  
  return (
    <AppBar sx={{backgroundColor: theme ? colors.headerDarkColor  : colors.headerLightColor}} position="static">
        <Drawer sx={{
          ".MuiDrawer-paper": {backgroundColor: theme ? colors.drawerDarkColor : colors.drawerLightColor,color: theme ? colors.darkText : colors.lightText ,},
        }} open={isOpen} onClose={()=>setOpen(false)}>
          <Box sx={{width:"300px",padding:"10px"}}>
            <List>
              {pages.map((pages, index) => (
                <ListItem key={pages.title} disablePadding onClick={()=>Forward(pages.link)}>
                  <ListItemButton>
                    <ListItemIcon sx={{color:theme ? colors.darkText : colors.lightText}}>
                      {pages.icon}
                    </ListItemIcon>
                    <ListItemText primary={pages.title} />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>
          </Box>
        </Drawer>

        <Toolbar>
            <IconButton
            size="medium"
            edge="start"
            color="inherit"
            aria-label="menu"
            sx={{ mr: 2 }}
            onClick={()=>setOpen(true)}
            >
            <MenuIcon />
            </IconButton>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                ScanFully
            </Typography>
            <IconButton onClick={()=>iconChangeTheme()}>
              {
                theme ? <WbSunnyIcon sx={{cursor:"pointer",color:"yellow"}}/> : <DarkModeIcon sx={{cursor:"pointer",color:"black"}}/>
              }
            </IconButton>
        </Toolbar>
    </AppBar>
  )
}

export default Appbar