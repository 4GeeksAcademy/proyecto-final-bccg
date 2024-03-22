import React, { useState, useEffect, useContext, useCallback } from "react";
import { useParams, Link } from "react-router-dom"; // Importa Link desde react-router-dom
import { Container } from "react-bootstrap";
import { Context } from "../store/appContext";
import debounce from 'lodash.debounce';

export const BookDetails = () => {
    const { id } = useParams();
    const { store, actions } = useContext(Context);
    const [bookDetails, setBookDetails] = useState(null);
    const [author, setAuthor] = useState(null);

    useEffect(() => {
        fetchBookDetails();
    }, [id]);

    const fetchBookDetails = async () => {
        try {
            const response = await fetch(`https://openlibrary.org/works/${id}.json`);
            if (!response.ok) {
                throw new Error("Error fetching book details");
            }
            const data = await response.json();
            setBookDetails(data);
            if (data && data.authors && data.authors[0]) {
                authorDetails(data.authors[0].author.key);
            }
        } catch (error) {
            console.error('Error fetching book details:', error);
        }
    };

    const authorDetails = useCallback(debounce(async (authorKey) => {
        try {
            const details = await fetch(`https://openlibrary.org${authorKey}.json`);
            const authorData = await details.json();
            setAuthor(authorData);
        } catch (error) {
            console.error("Error fetching author details:", error);
        }
    }, 500), []);

    // Render loading state until bookDetails and author are fetched
    if (!bookDetails || !author) {
        return <div>Cargando...</div>;
    } else {
        return (
            <Container>
                <div className="container-fluid d-flex bg-light"> 
                    <div className="m-2">
                        <img src={`https://covers.openlibrary.org/b/id/${bookDetails.covers}-L.jpg`} alt="Portada del libro" />
                    </div>
                    <div>
                        <h2>{bookDetails.title}</h2>
                        <p>Author: {author.name}</p>
                        <p>Year of Publication: {bookDetails.first_publish_date}</p>
                        <p>Description: {typeof bookDetails.description === 'string' ? bookDetails.description : bookDetails.description?.value}</p>
                        <p>ISBN: {bookDetails.isbn}</p>
                        <Link to={`/books/works/${id}/reviews`}>
                            <button className="btn btn-success">LEAVE A REVIEW</button>
                        </Link>
                    </div>
                    
                </div>
            </Container>
        );
    }
};

export default BookDetails;
