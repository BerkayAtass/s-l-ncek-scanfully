import { configureStore } from '@reduxjs/toolkit'
import constantSlice from "./constantSlice"

export const store = configureStore({
  reducer: {
    constant: constantSlice
  },
})