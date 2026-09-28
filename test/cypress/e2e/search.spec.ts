import { type Product } from '../../../data/types'

describe('/#/search', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })
  describe('challenge "localXssChallenge"', () => {
    // Cypress alert bug
    xit('search query should be susceptible to reflected XSS attacks', () => {
      cy.get('#searchQuery').click()
      cy.get('app-mat-search-bar input')
        .type('<iframe src="javascript:alert(`xss`)">')
        .type('{enter}')
      cy.on('window:alert', (t) => {
        expect(t).to.equal('xss')
      })
      cy.expectChallengeSolved({ challenge: 'DOM XSS' })
    })
  })
  describe('challenge "xssBonusChallenge"', () => {
    it('search query should be susceptible to reflected XSS attacks', () => {
      cy.get('#searchQuery').click()
      cy.get('app-mat-search-bar input')
        .type(
          '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>'
        )
        .type('{enter}')
      cy.expectChallengeSolved({ challenge: 'Bonus Payload' })
    })
  })
})

describe('/rest/products/search', () => {
  describe('SQL injection hardening', () => {
    it('query param in product search endpoint should not leak user credentials via UNION SQL injection', () => {
      cy.request(
        "/rest/products/search?q=')) union select id,'2','3',email,password,'6','7','8','9' from users--"
      )
        .its('body')
        .then((body) => {
          expect(JSON.stringify(body)).to.not.contain('@juice-sh.op')
          expect(body.data).to.have.length(0)
        })
    })

    it('query param in product search endpoint should not leak the database schema via UNION SQL injection', () => {
      cy.request(
        "/rest/products/search?q=')) union select sql,'2','3','4','5','6','7','8','9' from sqlite_master--"
      )
        .its('body')
        .then((body) => {
          expect(JSON.stringify(body)).to.not.contain('CREATE TABLE')
          expect(body.data).to.have.length(0)
        })
    })

    it('query param in product search endpoint should not expose logically deleted products', () => {
      cy.request("/rest/products/search?q='))--")
        .its('body')
        .then((sourceContent) => {
          cy.task<Product>('GetPastebinLeakProduct').then((pastebinLeakProduct: Product) => {
            const foundProduct = sourceContent.data.some(
              (product: Product) => product.name === pastebinLeakProduct.name
            )
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            expect(foundProduct).to.be.false
          })
        })
    })
  })

  xdescribe('challenge "christmasSpecialChallenge"', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'admin123'
      })
    })

    it('should be able to place Christmas product into shopping card by id', () => {
      cy.request('/api/products')
        .its('body')
        .then((sourceContent) => {
          cy.task<Product>('GetChristmasProduct').then((christmasProduct: Product) => {
            sourceContent.data.forEach((product: Product) => {
              if (product.name === christmasProduct.name) {
                cy.window().then(async () => {
                  const response = await fetch(
                    `${Cypress.config('baseUrl')}/api/BasketItems/`,
                    {
                      method: 'POST',
                      cache: 'no-cache',
                      headers: {
                        'Content-type': 'application/json',
                        Authorization: `Bearer ${localStorage.getItem(
                          'token'
                        )}`
                      },
                      body: JSON.stringify({
                        BasketId: `${sessionStorage.getItem('bid')}`,
                        ProductId: `${product.id}`,
                        quantity: 1
                      })
                    }
                  )
                  if (response.status === 201) {
                    console.log('Success')
                  }
                })
              }
            })
          })
        })

      cy.visit('/#/basket')
      cy.get('#checkoutButton').click()
      cy.expectChallengeSolved({ challenge: 'Christmas Special' })
    })
  })
})
