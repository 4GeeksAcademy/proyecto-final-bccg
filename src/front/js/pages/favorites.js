import React, { useState, createContext, useContext, useEffect } from 'react';


// Creamos el contexto para manejar los favoritos
export const FavoritesContext = createContext({
  favorites: [],
  addToFavorites: () => {},
  removeFromFavorites: () => {},
  isFavorite: () => false,
});

// Definimos el componente FavoritesPage fuera de FavoritesProvider
export const FavoritesPage = () => {
  return (
    <div>
      <h1>Mis favoritos</h1>
      {/* Otro contenido relacionado con los favoritos */}
    </div>
  );
};

// Creamos el proveedor de contexto para los favoritos
export const FavoritesProvider = ({ children }) => {
  // Estado para almacenar los favoritos del usuario
  const [favorites, setFavorites] = useState(() => {
    try {
      const savedFavorites = localStorage.getItem('favorites');
      return savedFavorites ? JSON.parse(savedFavorites) : [];
    } catch (error) {
      console.error('Error al recuperar favoritos del localStorage:', error);
      return [];
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem('favorites', JSON.stringify(favorites));
      console.log('Favoritos guardados en localStorage:', favorites);
    } catch (error) {
      console.error('Error al guardar favoritos en el localStorage:', error);
    }
  }, [favorites]);

  // Función para agregar un libro a los favoritos
  const addToFavorites = (book) => {
    try {
      if (!favorites.find((b) => b.key === book.key)) {
        setFavorites([...favorites, book]);
      }
    } catch (error) {
      console.error('Error al agregar libro a favoritos:', error);
    }
  };

  // Función para eliminar un libro de los favoritos
  const removeFromFavorites = (bookKey) => {
    try {
      setFavorites(favorites.filter((book) => book.key !== bookKey));
    } catch (error) {
      console.error('Error al eliminar libro de favoritos:', error);
    }
  };

  // Función para verificar si un libro es favorito
  const isFavorite = (bookKey) => {
    return Boolean(favorites.find((book) => book.key === bookKey));
  };

  // Retornamos el contexto con los valores y funciones necesarios
  return (
    <FavoritesContext.Provider value={{ favorites, addToFavorites, removeFromFavorites, isFavorite }}>
      {children}
      
    </FavoritesContext.Provider>
  );
};

// Hook personalizado para acceder al contexto de favoritos
export const useFavoritesContext = () => useContext(FavoritesContext);